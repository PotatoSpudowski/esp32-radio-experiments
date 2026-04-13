# ESP32 Radio Experiments

Learning radio security by building a secure link from scratch on 2 ESP32s over ESP-NOW.

Covers FHSS, encryption, authenticated encryption, key exchange, anti-replay, and jam resistance.

## Hardware

Two ESP32-D0WD-V3 NodeMCUs connected via USB.

## Build

Requires [PlatformIO](https://platformio.org/).

```bash
# flash TX
pio run -e tx -t upload

# flash RX
pio run -e rx -t upload

# flash jammer (3rd ESP32)
pio run -e jammer -t upload
```

## Structure

```
src/main.cpp              # full firmware (~1100 lines)
tools/attack_analysis.py  # red team attack analysis
platformio.ini            # build configs
```

## Run attack analysis

```bash
python3 tools/attack_analysis.py
```

## Blog post

[building a secure radio link on two esp32s](https://potatospudowski.github.io/articles/radio-security-from-scratch)
