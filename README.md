# Lightweight Authenticated Sensing with Replay, Tamper and False-Data Detection

[![PlatformIO](https://img.shields.io/badge/PlatformIO-Compatible-orange.svg)](https://platformio.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Hardware: ATmega328P + STM32L476RG](https://img.shields.io/badge/Hardware-Nano%20%2B%20Nucleo--L476RG-brightgreen.svg)]()
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)

An end-to-end, reproducible embedded security framework for resource-constrained IoT sensor nodes. Designed for an IEEE-style experimental evaluation, this project demonstrates authenticated sensing, cryptographic tamper protection, non-volatile sequence anti-replay tracking, pre-cryptographic rate limiting, and physical plausibility filtering across a heterogeneous 8-bit AVR to 32-bit ARM Cortex-M4 topology.

---

## 1. System Architecture

```
+------------------+         +----------------------+         +-----------------------+         +------------------+
| DS18B20 Sensor   | OneWire | Arduino Nano Clone   | UART TX | STM32 Nucleo-L476RG   | USB VCP | PC Host          |
| Waterproof Probe |-------->| (ATmega328P, 16 MHz) |-------->| (Cortex-M4, 80 MHz)   |-------->| (Python Attack   |
| 10-bit / D2 Pin  |         | Signs 16B Frame      | 1k/2k   | 5-Stage Verification  | ST-Link | & Eval Suite)    |
+------------------+         +----------------------+ Divider +-----------------------+         +------------------+
```

### The 5-Stage Verification Pipeline

The verifier executes defense checks in a strictly ordered pipeline. Early stages reject malicious or abnormal packets before expensive downstream operations execute:

```
  Incoming 16-Byte Wire Packet
              |
              v
    +-------------------+
    | 1. Rate Limiter   |---> [> 5 pkt/s] -------------> Log "FLOOD" (Drops BEFORE Crypto!)
    +-------------------+                                (~120 cycles / 1.5 µs)
              |
              v
    +-------------------+
    | 2. HMAC-SHA256    |---> [Tag Mismatch] -----------> Log "TAMPER"
    +-------------------+     (Constant-Time 64-bit)     (~42,000 cycles)
              |
              v
    +-------------------+
    | 3. Sequence Count |---> [Counter <= Last Seen] ---> Log "REPLAY"
    +-------------------+     (Monotonic / Anti-Replay)
              |
              v
    +-------------------+
    | 4. Plausibility   |---> [Out of Bounds / Jump] ---> Log "FALSE_DATA"
    +-------------------+     ([-10°C to +85°C, <=5°C/s])
              |
              v
    +-------------------+
    | 5. Accept & State |---> Valid Authenticated Sensor Data Accepted
    +-------------------+     (State updated ONLY after all checks pass)
```

1. **Pre-Crypto Rate Limiter:** Evaluates packet arrival rate before computing any cryptographic operations. Bursts exceeding 5 packets/second are dropped in **~120 cycles (1.5 µs)**, preventing Denial-of-Service CPU exhaustion.
2. **Cryptographic Authentication (HMAC-SHA256):** Computes HMAC-SHA256 over the 7-byte payload and performs a constant-time comparison against the truncated 64-bit (8-byte) authentication tag. Detects single-bit wire tampering.
3. **Sequence Anti-Replay Check:** Verifies that the 32-bit counter is strictly greater than the last accepted counter. The sensor node persists its counter to EEPROM in 100-packet epochs and jumps forward by 100 on boot, ensuring node reboots never trigger replay false positives.
4. **Physical Plausibility Filter:** Evaluates whether readings conform to thermodynamic laws:
   - **Absolute range gating:** $-10.00^\circ\text{C} \le T \le +85.00^\circ\text{C}$
   - **Kinetic rate of change:** $|\Delta T| / \Delta t \le 5.0^\circ\text{C}/\text{s}$
5. **State Update:** Internal verifier state (`last_accepted_counter`, `last_accepted_temp`, `last_accepted_time`) is updated **only after** all checks pass, preventing unauthenticated state-poisoning attacks.

---

## 2. Hardware Bill of Materials & Wiring

### Bill of Materials
- **Sensor Node:** Arduino Nano clone (ATmega328P, 5 V logic, 16 MHz, 2 KB SRAM, 32 KB Flash)
- **Sensor:** DS18B20 waterproof digital temperature sensor (Maxim Integrated, 1-Wire protocol)
- **Verifier:** STM32 Nucleo-L476RG (ARM Cortex-M4 with FPU, 80 MHz, 3.3 V logic, 128 KB SRAM, 1 MB Flash)
- **Resistors:**
  - $1 \times 4.7\text{ k}\Omega$ (DS18B20 1-Wire pull-up to +5 V)
  - $1 \times 1\text{ k}\Omega$ (Voltage divider upper resistor)
  - $1 \times 2\text{ k}\Omega$ (Voltage divider lower resistor)

### Wiring Diagram

```
DS18B20 Temperature Probe
--------------------------
Red (VCC)   -----> Arduino Nano +5V
Black (GND) -----> Arduino Nano GND
Yellow/Blue -----> Arduino Nano D2
                   (Connect 4.7k resistor between D2 and +5V)

UART Inter-Board Link (5V -> 3.3V Logic Level Shift)
----------------------------------------------------
Arduino Nano TX (D1) -----> [ 1k Ohm Resistor ] -----> Junction Point -----> Nucleo PA10 (D2, USART1 RX)
                                                             |
                                                     [ 2k Ohm Resistor ]
                                                             |
Arduino Nano GND    -----------------------------------------+-------------> Nucleo GND (Common Reference)

PC USB Connections
------------------
Arduino Nano USB  -----> PC (Programming only; unplug D1 during uploads)
Nucleo ST-Link USB-----> PC (Dual Virtual COM Port for logging and attack injection)
```

> **Voltage Divider Note:**
> $$V_{\text{out}} = 5.0\text{ V} \times \frac{2\text{ k}\Omega}{1\text{ k}\Omega + 2\text{ k}\Omega} = 3.333\text{ V}$$
> This provides a safe, level-shifted signal for STM32 3.3 V logic (Nucleo pin PA10 is also 5 V tolerant).

---

## 3. Wire Protocol Specification

Packets are 16 bytes, big-endian network order, packed with zero padding:

```
+---------------+-----------+-----------------------+---------------------+-----------------------+
| Preamble (1B) | NodeID(1B)| Sequence Counter (4B) | Temperature (2B)    | Truncated HMAC (8B)   |
| 0xAA          | 0x01      | uint32_t (Big-Endian) | int16_t (C * 100)   | First 8 bytes of      |
| Byte 0        | Byte 1    | Bytes 2..5            | Bytes 6..7          | HMAC-SHA256 (Bytes 8..15)
+---------------+-----------+-----------------------+---------------------+-----------------------+
|<----------------- Authenticated Region (Bytes 1..7) ------------------->|
```

- **Preamble (`0xAA`):** Fixed byte for byte-stream synchronization.
- **Node ID (`0x01`):** 8-bit identifier for the transmitting sensor node.
- **Sequence Counter (4 Bytes):** 32-bit monotonically increasing counter.
- **Temperature (2 Bytes):** Signed 16-bit integer representing temperature in centi-degrees Celsius ($T \times 100$). Supports negative temperatures via standard 2's complement.
- **Truncated HMAC (8 Bytes):** Truncated 64-bit tag computed using HMAC-SHA256 over bytes 1..7 with the 128-bit pre-shared key.
- **Framing Timeout:** If the time between consecutive bytes exceeds **20 ms**, the verifier resets its reception buffer to recover from line glitches.

---

## 4. Repository Structure

```
secure-iot-sensing/
├── README.md                      # Comprehensive project documentation
├── LICENSE                        # MIT License
├── .gitignore                     # PlatformIO, IDE, and Python build ignores
├── secure_iot.code-workspace      # VS Code multi-root workspace definition
│
├── nano_node/                     # Arduino Nano sensor node firmware
│   ├── platformio.ini             # PlatformIO build configuration (atmelavr)
│   ├── include/
│   │   ├── protocol.h             # Wire packet struct, serialization & secret key
│   │   └── crypto_sha256.h        # C header for standalone SHA-256 / HMAC
│   └── src/
│       ├── main.cpp               # DS18B20 sampling, EEPROM counter & packet TX
│       └── crypto_sha256.cpp      # RFC 2104 compliant HMAC-SHA256 implementation
│
├── nucleo_verifier/               # STM32 Nucleo-L476RG verifier firmware
│   ├── platformio.ini             # PlatformIO build configuration (ststm32)
│   ├── include/
│   │   ├── protocol.h             # Identical wire protocol definitions
│   │   └── crypto_sha256.h        # Cryptographic declarations & constant-time compare
│   └── src/
│       ├── main.cpp               # 5-stage verification pipeline & DWT benchmarking
│       └── crypto_sha256.cpp      # Verifier HMAC-SHA256 implementation
│
├── pc_tools/                      # Python PC host attack, logging & evaluation suite
│   ├── requirements.txt           # Python dependencies (pyserial, pandas, matplotlib)
│   ├── protocol.py                # Python packet packing & HMAC-SHA256 reference
│   ├── attacker.py                # Automated attack suite (Tamper, Replay, Flood, False-Data)
│   ├── evaluator.py               # Metrics parser: True Positive Rate, False Positive Rate, cycles
│   ├── plot_results.py            # Generates IEEE publication-ready figures
│   └── README.md                  # Detailed PC tools manual
│
└── examples/
    └── milestone1_uart_echo/      # Initial hardware bringup test sketches
        ├── first_test_nano.cpp.txt
        └── first_test_nucleo.cpp.txt
```

---

## 5. Getting Started

### Prerequisites

1. **PlatformIO Core (CLI) or VS Code with PlatformIO IDE extension**
2. **Python 3.9+** with virtual environment support

### 1. Install PC Host Dependencies

```bash
cd pc_tools
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Build and Flash Firmwares

Open the folder in PlatformIO or flash via CLI:

#### Flash the Arduino Nano:
*(Disconnect wire D1 during flashing to avoid bootloader interference)*
```bash
pio run -d nano_node -t upload
```

#### Flash the STM32 Nucleo:
```bash
pio run -d nucleo_verifier -t upload
```

---

## 6. Running Security Evaluations

Connect the STM32 Nucleo to your PC via USB (identifies as a Virtual COM Port, e.g., `COM3` on Windows or `/dev/ttyACM0` on Linux).

### Step A: Capture Genuine Packets (Baseline)
```bash
python pc_tools/attacker.py --port COM3 --mode capture --count 1000
```
Captures 1,000 genuine packets into `pc_tools/captures/genuine_packets.csv` and `genuine_packets.bin`.

### Step B: Run Automated Attack Experiments (1,000 trials per attack)
```bash
python pc_tools/attacker.py --port COM3 --mode all --count 1000
```
This automatically executes:
1. **Clean Baseline:** Evaluates uncorrupted sequential traffic (verifies 0% False Positive Rate).
2. **Tamper Attack:** Injects random single-bit and multi-byte flips in payload and HMAC tag $\rightarrow$ Verified and logged as `TAMPER`.
3. **Replay Attack:** Injects previously accepted packets with stale counters $\rightarrow$ Verified and logged as `REPLAY`.
4. **Flood Attack:** Bursts high-speed packets (>100 pkt/s) $\rightarrow$ Dropped pre-crypto and logged as `FLOOD`.
5. **False-Data Attack:** Injects validly signed packets with out-of-bounds ($95^\circ\text{C}$) or rapid jump ($+15^\circ\text{C}/\text{s}$) data $\rightarrow$ Flagged and logged as `FALSE_DATA`.

### Step C: Parse Metrics and CPU Cycle Savings
```bash
python pc_tools/evaluator.py
```
Outputs IEEE-formatted summary tables showing Detection Rate (%), False Positive Rate (%), average DWT cycle latency, and CPU cycle reduction.

### Step D: Generate Publication Figures
```bash
python pc_tools/plot_results.py
```
Exports high-resolution charts to `pc_tools/results/`:
- `fig_detection_rates.png`: Detection accuracy across all threat vectors ($N=1,000$ per class).
- `fig_cycle_breakdown.png`: Verification pipeline latency and pre-crypto savings.
- `fig_temperature_trajectory.png`: Physical plausibility response to sudden step jumps.

---

## 7. Known-Answer Test (KAT) Vectors

Use these deterministic test vectors to verify consistent endianness, payload packing, and cryptographic tag generation across AVR, ARM, and Python:

### Pre-Shared Key (16 Bytes / 128 Bits)
```
Key: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
```

#### Test Vector 1: Standard Room Temperature (+24.00 °C)
- **Node ID:** `0x01`
- **Counter:** `1` (`0x00000001`)
- **Temperature:** `+24.00 °C` -> Raw `2400` (`0x0960`)
- **Serialized 7-Byte Payload:** `01 00 00 00 01 09 60`
- **Full HMAC-SHA256 (32 Bytes):**
  `ca 86 0f 63 f9 6b e4 73 8d 64 b9 eb fa a9 ec fe e8 ad e8 7f e9 a5 91 16 57 e3 5f b7 fb 62 e4 59`
- **Truncated 8-Byte Tag:** `ca 86 0f 63 f9 6b e4 73`
- **Full 16-Byte Wire Packet:**
  `AA 01 00 00 00 01 09 60 CA 86 0F 63 F9 6B E4 73`

#### Test Vector 2: Sub-Zero Negative Temperature (-5.50 °C)
- **Node ID:** `0x01`
- **Counter:** `100` (`0x00000064`)
- **Temperature:** `-5.50 °C` -> Raw `-550` (`0xFDDA`)
- **Serialized 7-Byte Payload:** `01 00 00 00 64 fd da`
- **Full HMAC-SHA256 (32 Bytes):**
  `80 f7 96 14 0f 03 99 03 fb cc 95 8d a1 86 db 72 fd 48 55 ab 11 b6 92 76 1b 1a 80 d4 ec 7f 4c a2`
- **Truncated 8-Byte Tag:** `80 f7 96 14 0f 03 99 03`
- **Full 16-Byte Wire Packet:**
  `AA 01 00 00 00 64 FD DA 80 F7 96 14 0F 03 99 03`

---

## 8. Experimental Results & Performance Highlights

| Metric | Measurement | Notes |
|---|---|---|
| **Tamper Detection Rate** | **100.0%** ($N=1,000$) | Single-bit and multi-byte corruptions |
| **Replay Detection Rate** | **100.0%** ($N=1,000$) | Historical counter rejection |
| **Flood Rejection Rate** | **100.0%** ($N=1,000$) | Rates $>5\text{ pkt/s}$ dropped immediately |
| **False-Data Detection Rate** | **100.0%** ($N=1,000$) | Step jumps $>5.0^\circ\text{C/s}$ and range limits |
| **False Positive Rate (FPR)** | **0.00%** ($N=1,000$) | Clean baseline traffic |
| **Pre-Crypto Flood Drop Cost** | **~120 cycles (~1.5 µs)** | STM32 Cortex-M4 @ 80 MHz |
| **Full HMAC-SHA256 Cost** | **~42,000 cycles (~525 µs)** | Software implementation (no HW crypto) |
| **CPU Cycle Reduction** | **99.7% savings** | Pre-crypto drop saves ~41,880 cycles/packet |

---

## 9. Threat Model Scope & Boundaries

In accordance with rigorous academic and engineering standards, the threat model covers:
- **Tampering:** Any unauthorized modification of the sensor data, node ID, counter, or cryptographic tag in transit.
- **Replay Attacks:** Eavesdropping and retransmitting previously captured legitimate packets.
- **Flood Attacks:** High-rate packet transmission attempting to exhaust receiver computational resources.
- **Physical False-Data Injection:** Insider attacks where an adversary possessing the secret key injects physically impossible temperature anomalies.

### Stated Architectural Limitations
- **Verifier State Volatility:** Anti-replay relies on the verifier maintaining its sequence counter in memory. If the verifier undergoes a cold reboot, an initial window exists where an adversary can replay recorded packets until the stream exceeds the captured sequence.
- **Pre-Crypto DoS Availability Trade-Off:** Because the rate limiter drops packets before cryptographic computation, an adversary flooding the channel can starve legitimate sensor packets (availability denial of service).
- **Pre-Shared Symmetric Key:** The scheme uses a static 128-bit key. Physical side-channel extraction or firmware readout from an unprotected microcontroller exposes the broadcast domain.

---

## 10. License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
