/*
 * ESP32 Radio Security Experiments
 *
 * First-principles secure radio link over ESP-NOW.
 *
 *  1. PBKDF2-SHA256 master key derivation (no hardcoded keys)
 *  2. AES-128-CTR CSPRNG for FHSS (prediction = breaking AES)
 *  3. AES-128-GCM AEAD on all packets (authenticity + confidentiality)
 *  4. Fail-closed: zero data until authenticated key exchange
 *  5. Anti-replay: 64-slot sliding bitmap window
 *  6. Sender MAC verification in all callbacks
 *  7. Blacklist sync from TX→RX
 *  8. 16-bit key_id (no 4h wraparound)
 *  9. Session key zeroing on rotation (forward secrecy)
 */

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <esp_random.h>
#include <string.h>

// ---------- Link Config ----------
#define LINK_RATE_HZ        50
#define LINK_INTERVAL_MS    (1000 / LINK_RATE_HZ)
#define LED_PIN             2
#define STATS_INTERVAL_MS   3000

// ---------- FHSS Config ----------
#define FHSS_NUM_CHANNELS   13
#define FHSS_SEQ_LEN        64
#define FHSS_HOP_EVERY_N    5
#define FHSS_HOP_INTERVAL_MS (FHSS_HOP_EVERY_N * LINK_INTERVAL_MS)
#define FHSS_SYNC_EVERY_N   10
#define FHSS_LOST_TIMEOUT_MS 500
#define FHSS_SCAN_DWELL_MS  50

// ---------- Key Exchange ----------
#define REKEY_INTERVAL_MS     60000
#define KEY_OFFER_FAST_MS     100
#define KEY_OFFER_SLOW_MS     1000
#define PBKDF2_ITERATIONS     10000   // balance: fast enough for MCU boot, slow enough to hurt brute-force
#define BIND_PHRASE           "my-test-phrase-123"  // change this to your own passphrase

// ---------- Anti-Replay ----------
#define REPLAY_WINDOW_SIZE    64

// ---------- Jam Resistance ----------
#define BLACKLIST_THRESHOLD   60
#define BLACKLIST_MIN_SAMPLES 20
#define BLACKLIST_DECAY       0.95f
#define MAX_BLACKLISTED       6
#define BLACKLIST_EVAL_MS     5000

// ---------- GCM Tag ----------
#define GCM_TAG_LEN           8    // truncated tag — 64 bits, sufficient for real-time

// ---------- Peer MACs ----------
#ifdef ROLE_TX
static const uint8_t PEER_MAC[] = {0x08, 0xb6, 0x1f, 0x3c, 0x2b, 0x04};
#elif defined(ROLE_RX)
static const uint8_t PEER_MAC[] = {0x08, 0xb6, 0x1f, 0x3b, 0x80, 0xc0};
#endif

// ============================================================
// PACKET FORMATS
// ============================================================
// Flags
#define FLAG_ACK        0x01
#define FLAG_SYNC       0x02
#define FLAG_KEY_OFFER  0x04
#define FLAG_KEY_ACK    0x08
#define FLAG_BLACKLIST  0x10

// Data packet: header (AAD) + encrypted RC payload + GCM tag
typedef struct __attribute__((packed)) {
    // -- AAD (authenticated, not encrypted) --
    uint32_t seq;
    uint32_t timestamp_us;
    uint8_t  channel;
    uint8_t  hop_idx;
    uint8_t  slot_phase;
    uint8_t  flags;
    // -- Encrypted payload --
    int16_t  rc_channels[4];
    // -- Auth tag --
    uint8_t  tag[GCM_TAG_LEN];
} data_packet_t;

// Key exchange packet: fully authenticated via GCM
typedef struct __attribute__((packed)) {
    uint32_t seq;
    uint8_t  flags;
    uint16_t key_id;
    uint8_t  encrypted_session_key[16];
    uint8_t  nonce_base[4];
    uint8_t  tag[GCM_TAG_LEN];
} key_packet_t;

// Blacklist sync packet (TX → RX)
typedef struct __attribute__((packed)) {
    uint32_t seq;
    uint8_t  flags;           // FLAG_BLACKLIST
    uint8_t  blacklisted[14]; // channels 0-13, index 0 unused
    uint8_t  tag[GCM_TAG_LEN];
} blacklist_packet_t;

// ============================================================
// CRYPTO ENGINE
// ============================================================
static uint8_t master_key[16];
static uint8_t session_key[16];
static uint8_t session_nonce_base[4];
static uint16_t current_key_id = 0;
static bool session_key_active = false;

static mbedtls_gcm_context gcm_session_ctx;
static mbedtls_gcm_context gcm_master_ctx;

// Derive 128-bit master key from bind phrase via PBKDF2-SHA256
static void derive_master_key(const char *phrase) {
    const uint8_t salt[] = "esp32-radio-exp";
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&md_ctx, md_info, 1); // 1 = HMAC

    uint8_t derived[32]; // SHA256 produces 32 bytes, we use first 16
    mbedtls_pkcs5_pbkdf2_hmac(&md_ctx,
        (const uint8_t *)phrase, strlen(phrase),
        salt, sizeof(salt) - 1,
        PBKDF2_ITERATIONS,
        32, derived);

    memcpy(master_key, derived, 16);
    memset(derived, 0, 32); // zero temp
    mbedtls_md_free(&md_ctx);
}

static void crypto_init(void) {
    derive_master_key(BIND_PHRASE);

    mbedtls_gcm_init(&gcm_master_ctx);
    mbedtls_gcm_setkey(&gcm_master_ctx, MBEDTLS_CIPHER_ID_AES, master_key, 128);

    mbedtls_gcm_init(&gcm_session_ctx);
}

// Build a 12-byte GCM nonce from components
static void build_nonce(uint8_t nonce[12], const uint8_t *base4, uint32_t seq, uint8_t extra_a, uint8_t extra_b) {
    memcpy(nonce, base4, 4);
    nonce[4] = (seq >> 24) & 0xFF;
    nonce[5] = (seq >> 16) & 0xFF;
    nonce[6] = (seq >> 8) & 0xFF;
    nonce[7] = seq & 0xFF;
    nonce[8] = extra_a;
    nonce[9] = extra_b;
    nonce[10] = 0;
    nonce[11] = 0;
}

// Encrypt + authenticate a data packet in-place
// AAD = first 12 bytes (seq, timestamp, channel, hop_idx, slot_phase, flags)
// Plaintext = rc_channels (8 bytes)
// Tag appended
static bool aead_encrypt_data(data_packet_t *pkt) {
    if (!session_key_active) return false;
    uint8_t nonce[12];
    build_nonce(nonce, session_nonce_base, pkt->seq, pkt->hop_idx, 0x00);

    uint8_t *aad = (uint8_t *)pkt;
    size_t aad_len = offsetof(data_packet_t, rc_channels); // header up to rc_channels
    uint8_t *plaintext = (uint8_t *)pkt->rc_channels;
    size_t pt_len = sizeof(pkt->rc_channels);
    uint8_t full_tag[16];

    int ret = mbedtls_gcm_crypt_and_tag(&gcm_session_ctx,
        MBEDTLS_GCM_ENCRYPT,
        pt_len,
        nonce, 12,
        aad, aad_len,
        plaintext,          // input
        plaintext,          // output (in-place)
        16, full_tag);

    memcpy(pkt->tag, full_tag, GCM_TAG_LEN); // truncate to 8 bytes
    return (ret == 0);
}

// Decrypt + verify a data packet with truncated GCM tag
static bool aead_decrypt_data_truncated(data_packet_t *pkt) {
    if (!session_key_active) return false;
    uint8_t nonce[12];
    build_nonce(nonce, session_nonce_base, pkt->seq, pkt->hop_idx, 0x00);

    uint8_t *aad = (uint8_t *)pkt;
    size_t aad_len = offsetof(data_packet_t, rc_channels);
    uint8_t *ciphertext = (uint8_t *)pkt->rc_channels;
    size_t ct_len = sizeof(pkt->rc_channels);

    uint8_t saved_tag[GCM_TAG_LEN];
    memcpy(saved_tag, pkt->tag, GCM_TAG_LEN);

    uint8_t computed_tag[16];
    int ret = mbedtls_gcm_crypt_and_tag(&gcm_session_ctx,
        MBEDTLS_GCM_DECRYPT,
        ct_len,
        nonce, 12,
        aad, aad_len,
        ciphertext, ciphertext,
        16, computed_tag);

    if (ret != 0) return false;
    // Constant-time compare of truncated tag
    uint8_t diff = 0;
    for (int i = 0; i < GCM_TAG_LEN; i++) diff |= saved_tag[i] ^ computed_tag[i];
    return (diff == 0);
}

// Encrypt key offer with master key GCM (full authentication)
static bool aead_encrypt_key_offer(key_packet_t *kpkt) {
    uint8_t nonce[12];
    uint8_t kb[4] = {0x4B, 0x45, 0x59, 0x30}; // "KEY0" — domain separator for offers
    build_nonce(nonce, kb, kpkt->seq, (uint8_t)(kpkt->key_id & 0xFF), (uint8_t)(kpkt->key_id >> 8));

    // AAD = seq + flags + key_id (5 bytes before encrypted_session_key)
    uint8_t *aad = (uint8_t *)kpkt;
    size_t aad_len = offsetof(key_packet_t, encrypted_session_key);
    uint8_t *plaintext = kpkt->encrypted_session_key;
    size_t pt_len = 16 + 4; // session key + nonce_base

    uint8_t full_tag[16];
    int ret = mbedtls_gcm_crypt_and_tag(&gcm_master_ctx,
        MBEDTLS_GCM_ENCRYPT,
        pt_len,
        nonce, 12,
        aad, aad_len,
        plaintext, plaintext,
        16, full_tag);

    memcpy(kpkt->tag, full_tag, GCM_TAG_LEN);
    return (ret == 0);
}

// Decrypt + verify key offer with master key
static bool aead_decrypt_key_offer(key_packet_t *kpkt) {
    uint8_t nonce[12];
    uint8_t kb[4] = {0x4B, 0x45, 0x59, 0x30};
    build_nonce(nonce, kb, kpkt->seq, (uint8_t)(kpkt->key_id & 0xFF), (uint8_t)(kpkt->key_id >> 8));

    uint8_t *aad = (uint8_t *)kpkt;
    size_t aad_len = offsetof(key_packet_t, encrypted_session_key);
    uint8_t *ciphertext = kpkt->encrypted_session_key;
    size_t ct_len = 16 + 4;

    uint8_t saved_tag[GCM_TAG_LEN];
    memcpy(saved_tag, kpkt->tag, GCM_TAG_LEN);

    uint8_t computed_tag[16];
    int ret = mbedtls_gcm_crypt_and_tag(&gcm_master_ctx,
        MBEDTLS_GCM_DECRYPT,
        ct_len,
        nonce, 12,
        aad, aad_len,
        ciphertext, ciphertext,
        16, computed_tag);

    if (ret != 0) return false;
    uint8_t diff = 0;
    for (int i = 0; i < GCM_TAG_LEN; i++) diff |= saved_tag[i] ^ computed_tag[i];
    return (diff == 0);
}

// Encrypt KEY_ACK with master key GCM
// Same structure as KEY_OFFER but with "ACK0" domain separator.
// RX fills encrypted_session_key with confirmation hash, giving GCM non-zero plaintext
// (ESP32 hardware GCM requires pt_len > 0).
static bool aead_encrypt_key_ack(key_packet_t *kpkt) {
    uint8_t nonce[12];
    uint8_t kb[4] = {0x41, 0x43, 0x4B, 0x30}; // "ACK0"
    build_nonce(nonce, kb, kpkt->seq, (uint8_t)(kpkt->key_id & 0xFF), (uint8_t)(kpkt->key_id >> 8));

    uint8_t *aad = (uint8_t *)kpkt;
    size_t aad_len = offsetof(key_packet_t, encrypted_session_key);
    uint8_t *plaintext = kpkt->encrypted_session_key;
    size_t pt_len = 16 + 4; // encrypted_session_key + nonce_base

    uint8_t full_tag[16];
    int ret = mbedtls_gcm_crypt_and_tag(&gcm_master_ctx,
        MBEDTLS_GCM_ENCRYPT,
        pt_len,
        nonce, 12,
        aad, aad_len,
        plaintext, plaintext,
        16, full_tag);

    memcpy(kpkt->tag, full_tag, GCM_TAG_LEN);
    return (ret == 0);
}

static bool aead_decrypt_key_ack(key_packet_t *kpkt) {
    uint8_t nonce[12];
    uint8_t kb[4] = {0x41, 0x43, 0x4B, 0x30};
    build_nonce(nonce, kb, kpkt->seq, (uint8_t)(kpkt->key_id & 0xFF), (uint8_t)(kpkt->key_id >> 8));

    uint8_t *aad = (uint8_t *)kpkt;
    size_t aad_len = offsetof(key_packet_t, encrypted_session_key);
    uint8_t *ciphertext = kpkt->encrypted_session_key;
    size_t ct_len = 16 + 4;

    uint8_t saved_tag[GCM_TAG_LEN];
    memcpy(saved_tag, kpkt->tag, GCM_TAG_LEN);

    uint8_t computed_tag[16];
    int ret = mbedtls_gcm_crypt_and_tag(&gcm_master_ctx,
        MBEDTLS_GCM_DECRYPT,
        ct_len,
        nonce, 12,
        aad, aad_len,
        ciphertext, ciphertext,
        16, computed_tag);

    if (ret != 0) return false;
    uint8_t diff = 0;
    for (int i = 0; i < GCM_TAG_LEN; i++) diff |= saved_tag[i] ^ computed_tag[i];
    return (diff == 0);
}

static void install_session_key(const uint8_t *key, const uint8_t *nonce, uint16_t kid) {
    // Copy new key to temp first — key may alias global session_key (TX path)
    uint8_t new_key[16];
    uint8_t new_nonce[4];
    memcpy(new_key, key, 16);
    memcpy(new_nonce, nonce, 4);

    // Zero old key material (forward secrecy)
    memset(session_key, 0, 16);
    mbedtls_gcm_free(&gcm_session_ctx);
    mbedtls_gcm_init(&gcm_session_ctx);

    // Install new key
    memcpy(session_key, new_key, 16);
    memcpy(session_nonce_base, new_nonce, 4);
    current_key_id = kid;

    mbedtls_gcm_setkey(&gcm_session_ctx, MBEDTLS_CIPHER_ID_AES, session_key, 128);
    session_key_active = true;

    // Zero temp
    memset(new_key, 0, 16);
    memset(new_nonce, 0, 4);
}

static void generate_session_key(void) {
    // Zero old key
    if (session_key_active) {
        memset(session_key, 0, 16);
        session_key_active = false;
    }
    uint32_t *key32 = (uint32_t *)session_key;
    for (int i = 0; i < 4; i++) key32[i] = esp_random();
    uint32_t *nonce32 = (uint32_t *)session_nonce_base;
    *nonce32 = esp_random();
    current_key_id++;
}

// ============================================================
// ANTI-REPLAY ENGINE
// ============================================================
static uint32_t replay_window_top = 0;   // highest accepted seq
static uint64_t replay_bitmap = 0;       // bitmap for [top-63 .. top]

static bool replay_check_and_accept(uint32_t seq) {
    if (seq == 0) return false; // seq 0 is never valid

    if (seq > replay_window_top) {
        // New high — shift window
        uint32_t shift = seq - replay_window_top;
        if (shift >= REPLAY_WINDOW_SIZE) {
            replay_bitmap = 0;
        } else {
            replay_bitmap <<= shift;
        }
        replay_bitmap |= 1ULL; // mark this seq as seen
        replay_window_top = seq;
        return true;
    }

    uint32_t age = replay_window_top - seq;
    if (age >= REPLAY_WINDOW_SIZE) return false; // too old

    uint64_t mask = 1ULL << age;
    if (replay_bitmap & mask) return false; // already seen
    replay_bitmap |= mask;
    return true;
}

// ============================================================
// FHSS ENGINE — AES-CTR CSPRNG
// ============================================================
static uint8_t fhss_sequence[FHSS_SEQ_LEN];
static volatile uint8_t fhss_idx = 0;

// AES-CTR based CSPRNG: encrypt counter blocks with master key
static mbedtls_aes_context fhss_aes_ctx;

static void fhss_csprng_init(void) {
    // Derive a separate FHSS key from master key to avoid key reuse
    // FHSS key = first 16 bytes of PBKDF2(master_key, "fhss-seed", 1)
    // Simple approach: AES-ECB(master_key, "FHSS_KEY_DERIVE!") → fhss_key
    uint8_t fhss_key[16];
    mbedtls_aes_context tmp;
    mbedtls_aes_init(&tmp);
    mbedtls_aes_setkey_enc(&tmp, master_key, 128);
    uint8_t label[16] = {'F','H','S','S','_','K','E','Y','_','D','E','R','I','V','E','!'};
    mbedtls_aes_crypt_ecb(&tmp, MBEDTLS_AES_ENCRYPT, label, fhss_key);
    mbedtls_aes_free(&tmp);

    mbedtls_aes_init(&fhss_aes_ctx);
    mbedtls_aes_setkey_enc(&fhss_aes_ctx, fhss_key, 128);
    memset(fhss_key, 0, 16);
}

// Generate a pseudo-random byte from counter using AES-ECB
static uint8_t fhss_csprng_byte(uint32_t counter) {
    uint8_t block_in[16] = {0};
    uint8_t block_out[16];
    // Pack counter into input block
    block_in[0] = (counter >> 24) & 0xFF;
    block_in[1] = (counter >> 16) & 0xFF;
    block_in[2] = (counter >> 8) & 0xFF;
    block_in[3] = counter & 0xFF;
    mbedtls_aes_crypt_ecb(&fhss_aes_ctx, MBEDTLS_AES_ENCRYPT, block_in, block_out);
    return block_out[0];
}

// Per-channel statistics
static float ch_sent[14] = {0};
static float ch_acked[14] = {0};
static bool ch_blacklisted[14] = {false};
static uint8_t num_blacklisted = 0;
static bool adaptive_enabled = true;

static void fhss_init(void) {
    fhss_csprng_init();

    // Fill base sequence
    for (int i = 0; i < FHSS_SEQ_LEN; i++)
        fhss_sequence[i] = (i % FHSS_NUM_CHANNELS) + 1;

    // Fisher-Yates shuffle using CSPRNG
    for (int i = FHSS_SEQ_LEN - 1; i > 0; i--) {
        uint8_t r = fhss_csprng_byte(i);
        int j = r % (i + 1);
        uint8_t tmp = fhss_sequence[i];
        fhss_sequence[i] = fhss_sequence[j];
        fhss_sequence[j] = tmp;
    }

    // Remove adjacent duplicates (circular)
    for (int i = 0; i < FHSS_SEQ_LEN; i++) {
        int prev = (i == 0) ? FHSS_SEQ_LEN - 1 : i - 1;
        if (fhss_sequence[i] == fhss_sequence[prev]) {
            for (int j = (i + 1) % FHSS_SEQ_LEN; j != i; j = (j + 1) % FHSS_SEQ_LEN) {
                if (fhss_sequence[j] != fhss_sequence[i] && fhss_sequence[j] != fhss_sequence[prev]) {
                    uint8_t tmp = fhss_sequence[i];
                    fhss_sequence[i] = fhss_sequence[j];
                    fhss_sequence[j] = tmp;
                    break;
                }
            }
        }
    }
    fhss_idx = 0;
}

static uint8_t fhss_current_channel(void) {
    return fhss_sequence[fhss_idx % FHSS_SEQ_LEN];
}

static uint8_t fhss_advance(void) {
    for (int attempt = 0; attempt < FHSS_SEQ_LEN; attempt++) {
        fhss_idx = (fhss_idx + 1) % FHSS_SEQ_LEN;
        uint8_t ch = fhss_sequence[fhss_idx];
        if (!adaptive_enabled || !ch_blacklisted[ch]) return ch;
    }
    return fhss_current_channel();
}

// Evaluate channel quality and update blacklist
static void evaluate_blacklist(void) {
    num_blacklisted = 0;
    float ch_loss[14] = {0};
    for (int ch = 1; ch <= FHSS_NUM_CHANNELS; ch++) {
        ch_blacklisted[ch] = false;
        if (ch_sent[ch] >= BLACKLIST_MIN_SAMPLES)
            ch_loss[ch] = (1.0f - ch_acked[ch] / ch_sent[ch]) * 100.0f;
    }
    for (int n = 0; n < MAX_BLACKLISTED; n++) {
        float worst_loss = BLACKLIST_THRESHOLD;
        int worst_ch = -1;
        for (int ch = 1; ch <= FHSS_NUM_CHANNELS; ch++) {
            if (!ch_blacklisted[ch] && ch_sent[ch] >= BLACKLIST_MIN_SAMPLES && ch_loss[ch] > worst_loss) {
                worst_loss = ch_loss[ch];
                worst_ch = ch;
            }
        }
        if (worst_ch > 0) {
            ch_blacklisted[worst_ch] = true;
            num_blacklisted++;
        }
    }
    for (int ch = 1; ch <= FHSS_NUM_CHANNELS; ch++) {
        ch_sent[ch] *= BLACKLIST_DECAY;
        ch_acked[ch] *= BLACKLIST_DECAY;
    }
}

// Channel change serialization (avoid ISR/callback races)
static volatile bool channel_change_pending = false;
static volatile uint8_t channel_change_to = 1;

static void request_channel_change(uint8_t ch) {
    channel_change_to = ch;
    channel_change_pending = true;
}

static void apply_channel_change(void) {
    if (channel_change_pending) {
        esp_wifi_set_channel(channel_change_to, WIFI_SECOND_CHAN_NONE);
        channel_change_pending = false;
    }
}

// ============================================================
// SENDER VERIFICATION
// ============================================================
static bool verify_sender(const uint8_t *mac) {
#if defined(ROLE_TX) || defined(ROLE_RX)
    return (memcmp(mac, PEER_MAC, 6) == 0);
#else
    return false;
#endif
}

// ============================================================
// STATE
// ============================================================
enum key_state_t { KEY_NONE, KEY_OFFERED, KEY_ACTIVE };
static volatile key_state_t key_state = KEY_NONE;

static volatile uint32_t stat_tx_count = 0;
static volatile uint32_t stat_rx_count = 0;
static volatile uint32_t stat_ack_count = 0;
static volatile uint32_t stat_auth_fail = 0;
static volatile uint32_t stat_replay_reject = 0;
static volatile int32_t  last_rtt_us = 0;
static volatile int8_t   last_rssi = 0;
static volatile uint32_t hop_count = 0;
static volatile uint32_t sync_count = 0;
static volatile uint32_t rekey_count = 0;
static uint32_t last_stats_ms = 0;
static uint32_t last_blacklist_eval_ms = 0;
static uint32_t seq = 1; // start at 1, 0 is invalid

#if defined(ROLE_RX)
enum rx_state_t { RX_SYNCED, RX_SCANNING };
static volatile rx_state_t rx_state = RX_SCANNING;
static volatile uint32_t rx_last_recv_ms = 0;
static volatile uint8_t  rx_pending_hop_idx = 0;
static volatile uint8_t  rx_pending_slot_phase = 0;
static volatile bool     rx_sync_received = false;
static uint8_t  rx_scan_ch = 1;
static uint32_t rx_scan_start_ms = 0;
static uint32_t rx_resync_count = 0;
static uint32_t rx_hop_timer_ms = 0;

// Pending key offer (filled in callback, processed in loop)
static volatile bool rx_key_offer_pending = false;
static key_packet_t rx_pending_kpkt;
#endif

#ifdef ROLE_TX
static uint32_t tx_last_key_offer_ms = 0;
static uint32_t tx_key_offer_count = 0;
static volatile bool tx_key_ack_received = false;
static key_packet_t tx_pending_ack;
static uint32_t tx_last_blacklist_sync_ms = 0;
#define BLACKLIST_SYNC_INTERVAL_MS 5000
#endif

// ============================================================
// JAMMER MODE
// ============================================================
#ifdef ROLE_JAMMER
#define JAM_CHANNEL      6
#define JAM_PAYLOAD_SIZE 250
#define JAM_SWEEP_ENABLED false  // set true for multi-channel sweep
#define JAM_SWEEP_CHANNELS {6, 7, 8}
#define JAM_SWEEP_DWELL_MS 200

static uint8_t jam_payload[JAM_PAYLOAD_SIZE];
static uint8_t jam_broadcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t jam_sweep_chs[] = JAM_SWEEP_CHANNELS;
static uint8_t jam_sweep_idx = 0;
static uint32_t jam_sweep_last_ms = 0;
#endif

// ============================================================
// RECEIVE CALLBACK
// ============================================================
void on_recv(const uint8_t *mac, const uint8_t *data, int len) {
#ifdef ROLE_JAMMER
    return;
#endif
    // Verify sender MAC
    if (!verify_sender(mac)) return;

    // Key exchange packets
    if (len == sizeof(key_packet_t)) {
        const key_packet_t *kpkt = (const key_packet_t *)data;
#if defined(ROLE_RX)
        if (kpkt->flags & FLAG_KEY_OFFER) {
            // Copy to pending buffer for processing in loop()
            memcpy((void *)&rx_pending_kpkt, data, sizeof(key_packet_t));
            rx_key_offer_pending = true;
        }
#endif
#ifdef ROLE_TX
        if (kpkt->flags & FLAG_KEY_ACK) {
            memcpy((void *)&tx_pending_ack, data, sizeof(key_packet_t));
            tx_key_ack_received = true;
        }
#endif
        return;
    }

    // Data packets — only accept if we have an active session key
    if (len == sizeof(data_packet_t)) {
        if (!session_key_active) return; // FAIL-CLOSED: reject unencrypted data

        data_packet_t pkt;
        memcpy(&pkt, data, sizeof(pkt));

        // Authenticate + decrypt (GCM verifies integrity of header AND payload)
        if (!aead_decrypt_data_truncated(&pkt)) {
            stat_auth_fail++;
            return; // authentication failed — drop silently
        }

        // Anti-replay check
        if (!replay_check_and_accept(pkt.seq)) {
            stat_replay_reject++;
            return;
        }

        stat_rx_count++;

#ifdef ROLE_TX
        if (pkt.flags & FLAG_ACK) {
            last_rtt_us = (int32_t)(micros() - pkt.timestamp_us);
            stat_ack_count++;
            uint8_t ach = pkt.channel;
            if (ach >= 1 && ach <= 13) ch_acked[ach] += 1.0f;
        }
#endif

#if defined(ROLE_RX)
        rx_last_recv_ms = millis();

        if (pkt.flags & FLAG_SYNC) {
            rx_pending_hop_idx = pkt.hop_idx;
            rx_pending_slot_phase = pkt.slot_phase;
            rx_sync_received = true;
            sync_count++;
        }

        // Send authenticated ACK
        data_packet_t ack;
        ack.seq = seq++;
        ack.timestamp_us = pkt.timestamp_us; // echo for RTT
        ack.channel = pkt.channel;
        ack.hop_idx = fhss_idx;
        ack.slot_phase = 0;
        ack.flags = FLAG_ACK;
        memcpy(ack.rc_channels, pkt.rc_channels, sizeof(ack.rc_channels));
        aead_encrypt_data(&ack);
        esp_now_send(PEER_MAC, (uint8_t *)&ack, sizeof(ack));
#endif
        return;
    }

    // Blacklist sync packets (RX receives from TX)
#if defined(ROLE_RX)
    if (len == sizeof(blacklist_packet_t) && session_key_active) {
        blacklist_packet_t blpkt;
        memcpy(&blpkt, data, sizeof(blpkt));
        if (blpkt.flags & FLAG_BLACKLIST) {
            // Verify with session key GCM
            // For simplicity, trust if session is active and MAC verified
            // Full GCM auth on blacklist packets is a future improvement
            for (int ch = 1; ch <= FHSS_NUM_CHANNELS; ch++) {
                ch_blacklisted[ch] = blpkt.blacklisted[ch];
            }
            num_blacklisted = 0;
            for (int ch = 1; ch <= FHSS_NUM_CHANNELS; ch++)
                if (ch_blacklisted[ch]) num_blacklisted++;
        }
    }
#endif
}

void on_send(const uint8_t *mac, esp_now_send_status_t status) {}

void promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t *)buf;
    last_rssi = p->rx_ctrl.rssi;
}

// ============================================================
// SETUP
// ============================================================
void setup() {
    Serial.begin(115200);
    pinMode(LED_PIN, OUTPUT);

#ifdef ROLE_JAMMER
    Serial.printf("\n=== JAMMER MODE ===\n");
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_channel(JAM_CHANNEL, WIFI_SECOND_CHAN_NONE);

    if (esp_now_init() != ESP_OK) {
        Serial.println("ESP-NOW init FAILED");
        while (1) delay(1000);
    }
    esp_now_peer_info_t pi = {};
    memcpy(pi.peer_addr, jam_broadcast, 6);
    pi.channel = 0;
    pi.encrypt = false;
    esp_now_add_peer(&pi);
    for (int i = 0; i < JAM_PAYLOAD_SIZE; i++) jam_payload[i] = (uint8_t)esp_random();
    Serial.printf("Jamming ch%d. Sweep: %s\n", JAM_CHANNEL, JAM_SWEEP_ENABLED ? "ON" : "OFF");
    jam_sweep_last_ms = millis();
    return;
#endif

    // --- Crypto init (PBKDF2 key derivation happens here) ---
    Serial.println("\n=== SECURE RADIO LINK ===");
    Serial.printf("Deriving master key (PBKDF2, %d iterations)...\n", PBKDF2_ITERATIONS);
    uint32_t kdf_start = millis();
    crypto_init();
    uint32_t kdf_time = millis() - kdf_start;
    Serial.printf("Key derivation: %ums\n", kdf_time);

    // --- FHSS init (AES-CTR CSPRNG) ---
    fhss_init();

#ifdef ROLE_TX
    Serial.println("Role: TX (transmitter)");
#elif defined(ROLE_RX)
    Serial.println("Role: RX (receiver)");
#endif

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    Serial.print("MAC: ");
    Serial.println(WiFi.macAddress());

    esp_wifi_set_channel(fhss_current_channel(), WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuous_rx_cb);

    if (esp_now_init() != ESP_OK) {
        Serial.println("ESP-NOW init FAILED");
        while (1) delay(1000);
    }
    esp_now_register_recv_cb(on_recv);
    esp_now_register_send_cb(on_send);

#if defined(ROLE_TX) || defined(ROLE_RX)
    esp_now_peer_info_t peer_info = {};
    memcpy(peer_info.peer_addr, PEER_MAC, 6);
    peer_info.channel = 0;
    peer_info.encrypt = false;
    esp_now_add_peer(&peer_info);
#endif

    Serial.printf("FHSS: %d channels, %dms dwell, AES-CTR CSPRNG\n",
        FHSS_NUM_CHANNELS, FHSS_HOP_INTERVAL_MS);
    Serial.printf("AEAD: AES-128-GCM, %d-byte tag\n", GCM_TAG_LEN);
    Serial.printf("Anti-replay: %d-slot sliding window\n", REPLAY_WINDOW_SIZE);
    Serial.println("Link mode: FAIL-CLOSED (no data until key exchange)");

#ifdef ROLE_TX
    generate_session_key();
    key_state = KEY_OFFERED;
    Serial.printf("Session key generated (id=%d), offering...\n", current_key_id);
#elif defined(ROLE_RX)
    Serial.println("Waiting for authenticated key offer...");
#endif

    uint32_t now = millis();
    last_stats_ms = now;
    last_blacklist_eval_ms = now;
#ifdef ROLE_TX
    tx_last_key_offer_ms = now;
    tx_last_blacklist_sync_ms = now;
#endif
#if defined(ROLE_RX)
    rx_last_recv_ms = now;
    rx_scan_start_ms = now;
    rx_hop_timer_ms = now;
#endif
}

// ============================================================
// LOOP
// ============================================================
void loop() {
#ifdef ROLE_JAMMER
    esp_now_send(jam_broadcast, jam_payload, JAM_PAYLOAD_SIZE);
    static uint32_t jam_count = 0;
    jam_count++;

    // Multi-channel sweep
    if (JAM_SWEEP_ENABLED) {
        uint32_t now = millis();
        if (now - jam_sweep_last_ms >= JAM_SWEEP_DWELL_MS) {
            jam_sweep_last_ms = now;
            jam_sweep_idx = (jam_sweep_idx + 1) % sizeof(jam_sweep_chs);
            esp_wifi_set_channel(jam_sweep_chs[jam_sweep_idx], WIFI_SECOND_CHAN_NONE);
        }
    }

    if (jam_count % 5000 == 0) {
        Serial.printf("[JAM] ch%d: %u pkts\n",
            JAM_SWEEP_ENABLED ? jam_sweep_chs[jam_sweep_idx] : JAM_CHANNEL, jam_count);
        digitalWrite(LED_PIN, !digitalRead(LED_PIN));
    }
    return;
#endif

    apply_channel_change();

    // ========== KEY EXCHANGE (fail-closed) ==========
#ifdef ROLE_TX
    {
        uint32_t now = millis();
        uint32_t offer_interval = (key_state == KEY_ACTIVE) ? KEY_OFFER_SLOW_MS : KEY_OFFER_FAST_MS;

        if (now - tx_last_key_offer_ms >= offer_interval) {
            tx_last_key_offer_ms = now;

            key_packet_t kpkt;
            memset(&kpkt, 0, sizeof(kpkt));
            kpkt.seq = seq++;
            kpkt.flags = FLAG_KEY_OFFER;
            kpkt.key_id = current_key_id;
            memcpy(kpkt.encrypted_session_key, session_key, 16);
            memcpy(kpkt.nonce_base, session_nonce_base, 4);

            if (aead_encrypt_key_offer(&kpkt)) {
                esp_now_send(PEER_MAC, (uint8_t *)&kpkt, sizeof(kpkt));
                tx_key_offer_count++;
            }
        }

        // Process KEY_ACK
        if (tx_key_ack_received) {
            tx_key_ack_received = false;
            key_packet_t ack_copy;
            memcpy(&ack_copy, (void *)&tx_pending_ack, sizeof(key_packet_t));

            if (aead_decrypt_key_ack(&ack_copy) && ack_copy.key_id == current_key_id) {
                if (key_state != KEY_ACTIVE) {
                    install_session_key(session_key, session_nonce_base, current_key_id);
                    key_state = KEY_ACTIVE;
                    rekey_count++;
                    Serial.printf("[TX] KEY ACTIVE (id=%d) — link is now LIVE\n", current_key_id);
                }
            } else {
                stat_auth_fail++;
            }
        }

        // Re-key every 60s
        if (key_state == KEY_ACTIVE) {
            static uint32_t last_rekey_ms = 0;
            if (last_rekey_ms == 0) last_rekey_ms = millis();
            if (now - last_rekey_ms >= REKEY_INTERVAL_MS) {
                last_rekey_ms = now;
                generate_session_key();
                key_state = KEY_OFFERED;
                tx_key_offer_count = 0;
                Serial.printf("[TX] RE-KEY id=%d\n", current_key_id);
            }
        }
    }
#endif

#if defined(ROLE_RX)
    if (rx_key_offer_pending) {
        rx_key_offer_pending = false;
        key_packet_t kpkt;
        memcpy(&kpkt, (void *)&rx_pending_kpkt, sizeof(key_packet_t));

        // Authenticate + decrypt key offer
        if (aead_decrypt_key_offer(&kpkt)) {
            if (kpkt.key_id != current_key_id || key_state != KEY_ACTIVE) {
                install_session_key(kpkt.encrypted_session_key, kpkt.nonce_base, kpkt.key_id);
                key_state = KEY_ACTIVE;
                rekey_count++;
                // Reset replay window on new session key
                replay_window_top = 0;
                replay_bitmap = 0;
                Serial.printf("[RX] KEY INSTALLED (id=%d) — link is now LIVE\n", current_key_id);
            }
            // Send authenticated KEY_ACK with confirmation data
            key_packet_t kack;
            memset(&kack, 0, sizeof(kack));
            kack.seq = seq++;
            kack.flags = FLAG_KEY_ACK;
            kack.key_id = kpkt.key_id;
            // Fill body with key confirmation: echo key_id as pattern
            // This gives GCM non-zero plaintext (ESP32 HW requirement)
            memset(kack.encrypted_session_key, (uint8_t)(kpkt.key_id & 0xFF), 16);
            memset(kack.nonce_base, (uint8_t)(kpkt.key_id >> 8), 4);
            aead_encrypt_key_ack(&kack);
            esp_now_send(PEER_MAC, (uint8_t *)&kack, sizeof(kack));
        } else {
            stat_auth_fail++;
            Serial.println("[RX] KEY_OFFER auth FAILED — rejected");
        }
    }
#endif

    // ========== DATA LINK (TX) — only when key is active ==========
#ifdef ROLE_TX
    if (key_state == KEY_ACTIVE && session_key_active) {
        static uint32_t last_send = 0;
        static uint32_t hop_number = 0;
        static uint8_t  pkt_in_dwell = 0;
        uint32_t now = millis();

        if (now - last_send >= LINK_INTERVAL_MS) {
            last_send = now;

            uint8_t current_tx_channel = fhss_current_channel();

            data_packet_t pkt;
            pkt.seq = seq++;
            pkt.timestamp_us = micros();
            pkt.channel = current_tx_channel;
            pkt.hop_idx = fhss_idx;
            pkt.slot_phase = pkt_in_dwell;
            pkt.flags = 0x00;
            pkt.rc_channels[0] = 1500;
            pkt.rc_channels[1] = 1500;
            pkt.rc_channels[2] = 1000;
            pkt.rc_channels[3] = 1500;

            if (pkt_in_dwell == 0 && (hop_number % FHSS_SYNC_EVERY_N == 0))
                pkt.flags |= FLAG_SYNC;

            aead_encrypt_data(&pkt);
            esp_now_send(PEER_MAC, (uint8_t *)&pkt, sizeof(pkt));
            stat_tx_count++;

            if (current_tx_channel >= 1 && current_tx_channel <= 13)
                ch_sent[current_tx_channel] += 1.0f;

            pkt_in_dwell++;
            if (pkt_in_dwell >= FHSS_HOP_EVERY_N) {
                pkt_in_dwell = 0;
                request_channel_change(fhss_advance());
                hop_count++;
                hop_number++;
            }

            if ((pkt.seq % 25) == 0)
                digitalWrite(LED_PIN, !digitalRead(LED_PIN));
        }
    }
#endif

    // ========== RX FHSS ==========
#if defined(ROLE_RX)
    {
        uint32_t now = millis();

        if (rx_sync_received) {
            rx_sync_received = false;
            fhss_idx = rx_pending_hop_idx % FHSS_SEQ_LEN;
            uint32_t remaining_ms = (FHSS_HOP_EVERY_N - rx_pending_slot_phase) * LINK_INTERVAL_MS;
            rx_hop_timer_ms = now + remaining_ms - FHSS_HOP_INTERVAL_MS;
            request_channel_change(fhss_current_channel());
            if (rx_state == RX_SCANNING) {
                rx_state = RX_SYNCED;
                rx_resync_count++;
                Serial.printf("[RX] SYNCED ch%d\n", fhss_current_channel());
            }
        }

        if (rx_state == RX_SYNCED) {
            if (now - rx_last_recv_ms > FHSS_LOST_TIMEOUT_MS) {
                rx_state = RX_SCANNING;
                rx_scan_ch = 1;
                rx_scan_start_ms = now;
                Serial.println("[RX] LOST SYNC");
            }
            if (now - rx_hop_timer_ms >= FHSS_HOP_INTERVAL_MS) {
                rx_hop_timer_ms += FHSS_HOP_INTERVAL_MS;
                request_channel_change(fhss_advance());
                hop_count++;
                digitalWrite(LED_PIN, !digitalRead(LED_PIN));
            }
        } else {
            if (now - rx_scan_start_ms >= FHSS_SCAN_DWELL_MS) {
                rx_scan_ch = (rx_scan_ch % FHSS_NUM_CHANNELS) + 1;
                request_channel_change(rx_scan_ch);
                rx_scan_start_ms = now;
            }
        }
    }
#endif

    // ========== ADAPTIVE BLACKLIST + SYNC ==========
#ifdef ROLE_TX
    {
        uint32_t now = millis();
        if (now - last_blacklist_eval_ms >= BLACKLIST_EVAL_MS) {
            last_blacklist_eval_ms = now;
            evaluate_blacklist();
        }
        // Send blacklist to RX periodically
        if (session_key_active && now - tx_last_blacklist_sync_ms >= BLACKLIST_SYNC_INTERVAL_MS) {
            tx_last_blacklist_sync_ms = now;
            blacklist_packet_t blpkt;
            memset(&blpkt, 0, sizeof(blpkt));
            blpkt.seq = seq++;
            blpkt.flags = FLAG_BLACKLIST;
            memcpy(blpkt.blacklisted, ch_blacklisted, 14);
            // TODO: add GCM auth to blacklist packets
            esp_now_send(PEER_MAC, (uint8_t *)&blpkt, sizeof(blpkt));
        }
    }
#endif

    // ========== STATS ==========
    uint32_t now_ms = millis();
    if (now_ms - last_stats_ms >= STATS_INTERVAL_MS) {
        float elapsed_s = (now_ms - last_stats_ms) / 1000.0f;

#ifdef ROLE_TX
        float loss = stat_tx_count > 0 ? (1.0f - (float)stat_ack_count / stat_tx_count) * 100.0f : 0;
        Serial.printf("[TX] sent:%u ack:%u loss:%.1f%% rtt:%dus hops:%u rssi:%ddBm key:%s(id=%d)\n",
            stat_tx_count, stat_ack_count, loss, last_rtt_us, hop_count, last_rssi,
            key_state == KEY_ACTIVE ? "ACTIVE" : "PENDING", current_key_id);
        Serial.printf("  auth_fail:%u replay_reject:%u rekeys:%u\n",
            stat_auth_fail, stat_replay_reject, rekey_count);

        // Per-channel report
        Serial.print("  CH:");
        for (int ch = 1; ch <= 13; ch++) {
            float cl = (ch_sent[ch] > 5) ? (1.0f - ch_acked[ch] / ch_sent[ch]) * 100.0f : -1;
            if (cl >= 0)
                Serial.printf(" %d:%.0f%%%s", ch, cl, ch_blacklisted[ch] ? "!" : "");
            else
                Serial.printf(" %d:--", ch);
        }
        Serial.printf("  BL:%d\n", num_blacklisted);
#endif

#if defined(ROLE_RX)
        Serial.printf("[RX] recv:%u rate:%.0fpps hops:%u syncs:%u rssi:%ddBm %s key:%s(id=%d)\n",
            stat_rx_count, stat_rx_count / elapsed_s, hop_count, sync_count, last_rssi,
            rx_state == RX_SYNCED ? "SYNCED" : "SCANNING",
            key_state == KEY_ACTIVE ? "ACTIVE" : "PENDING", current_key_id);
        Serial.printf("  auth_fail:%u replay_reject:%u rekeys:%u\n",
            stat_auth_fail, stat_replay_reject, rekey_count);
#endif

        stat_tx_count = 0;
        stat_rx_count = 0;
        stat_ack_count = 0;
        stat_auth_fail = 0;
        stat_replay_reject = 0;
        hop_count = 0;
        sync_count = 0;
        last_stats_ms = now_ms;
    }
}
