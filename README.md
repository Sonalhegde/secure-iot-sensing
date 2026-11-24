# Lightweight Authenticated Sensing with Replay, Tamper and False-Data Detection

[![PlatformIO](https://img.shields.io/badge/PlatformIO-Compatible-orange.svg)](https://platformio.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Hardware: ATmega328P + STM32L476RG](https://img.shields.io/badge/Hardware-Nano%20%2B%20Nucleo--L476RG-brightgreen.svg)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)

An end-to-end, reproducible embedded security framework for resource-constrained IoT sensor nodes. Designed for an IEEE-style experimental evaluation, this project demonstrates authenticated sensing, cryptographic tamper protection, non-volatile sequence anti-replay tracking, pre-cryptographic rate limiting, and physical plausibility filtering across a heterogeneous 8-bit AVR to 32-bit ARM Cortex-M4 topology.

---

## 1. System Architecture

```mermaid
flowchart LR
    DS["DS18B20 Sensor Probe"] -->|"OneWire (D2)"| Nano["Arduino Nano Node (ATmega328P, 16 MHz)"]
    Nano -->|"UART TX (D1)"| Div["Voltage Divider (1k / 2k to 3.3V)"]
    Div -->|"UART RX (PA10)"| Nucleo["STM32 Nucleo-L476RG (Cortex-M4, 80 MHz)"]
    Nucleo -->|"USB VCP (ST-Link)"| PC["PC Host (Python Attack & Telemetry HUD)"]
```

### The 5-Stage Verification Pipeline

The verifier executes defense checks in a strictly ordered pipeline. Early stages reject malicious or abnormal packets before expensive downstream operations execute:

```mermaid
flowchart TD
    Start(["Incoming 16-Byte Wire Packet"]) --> S1{"Stage 1: Rate Limiter"}
    S1 -->|"Rate > 5 pkt/s"| DropFlood["Drop Packet: Log FLOOD (Pre-Crypto Early Exit: 101 cycles / 1.26 us)"]
    S1 -->|"Rate <= 5 pkt/s"| S2{"Stage 2: HMAC-SHA256"}
    S2 -->|"Tag Mismatch"| DropTamper["Drop Packet: Log TAMPER (Constant-Time Check: ~22,889 cycles)"]
    S2 -->|"Tag Valid"| S3{"Stage 3: Sequence Counter"}
    S3 -->|"Counter <= Last Seen"| DropReplay["Drop Packet: Log REPLAY (Anti-Replay Window: ~22,993 cycles)"]
    S3 -->|"Counter > Last Seen"| S4{"Stage 4: Plausibility Filter"}
    S4 -->|"Range or Rate Anomaly"| DropFalse["Drop Packet: Log FALSE_DATA (Physics Check: ~23,123 cycles)"]
    S4 -->|"Physically Valid"| Accept["Stage 5: State Commit & Acceptance (Log ACCEPT & Output Hex: ~23,123 cycles)"]
```

1. **Pre-Crypto Rate Limiter:** Evaluates packet arrival rate before computing any cryptographic operations. Bursts exceeding 5 packets/second are dropped in **101 cycles (1.26 µs)**, preventing Denial-of-Service CPU exhaustion.
2. **Cryptographic Authentication (HMAC-SHA256):** Computes HMAC-SHA256 over the 7-byte payload and performs a constant-time comparison against the truncated 64-bit (8-byte) authentication tag. Detects single-bit wire tampering.
3. **Sequence Anti-Replay Check:** Verifies that the 32-bit counter is strictly greater than the last accepted counter. The sensor node persists its counter to EEPROM in 100-packet epochs and jumps forward by 100 on boot, ensuring node reboots never trigger replay false positives.
4. **Physical Plausibility Filter:** Evaluates whether readings conform to thermodynamic laws:
   - **Absolute range gating:** $-10.00^\circ\text{C} \le T \le +85.00^\circ\text{C}$
   - **Kinetic rate of change:** $|\Delta T| / \Delta t \le 5.0^\circ\text{C}/\text{s}$
5. **State Update:** Internal verifier state (`last_accepted_counter`, `last_accepted_temp`, `last_accepted_time`) is updated **only after** all checks pass, preventing unauthenticated state-poisoning attacks.

---

## 2. Telemetry Timing & State Machine

### Secure Telemetry Sequence
```mermaid
sequenceDiagram
    autonumber
    participant Sensor as DS18B20 Sensor
    participant Nano as Arduino Nano Node
    participant Wire as Level-Shifted UART
    participant Nucleo as STM32 Nucleo Verifier
    participant PC as PC Host (Mission Control HUD)

    loop Periodic Telemetry (1 Hz)
        Nano->>Sensor: requestTemperatures (10-bit, ~188 ms)
        Sensor-->>Nano: getTempCByIndex
        Nano->>Nano: Increment Sequence Counter (EEPROM sync every 100)
        Nano->>Nano: Serialize Payload (NodeID, Counter, Temp)
        Nano->>Nano: Compute HMAC-SHA256 (Truncate to 8 Bytes)
        Nano->>Wire: Transmit 16-Byte Wire Packet at 115200 baud
        Wire->>Nucleo: SerialNano PA10 (USART1 RX)
        Nucleo->>Nucleo: Stage 1: Rate Limiter (Max 5 pkt/s)
        Nucleo->>Nucleo: Stage 2: Constant-Time HMAC-SHA256 Validation
        Nucleo->>Nucleo: Stage 3: Monotonic Counter Freshness Check
        Nucleo->>Nucleo: Stage 4: Thermodynamic Plausibility Check
        Nucleo->>PC: Log CSV (LOG,ACCEPT,counter,temp,cycles)
        Nucleo->>PC: Stream Packet Hex (HEX,aa01...)
    end
```

### UART Frame Resync State Machine
```mermaid
stateDiagram-v2
    [*] --> WAIT_PREAMBLE: rx_index = 0
    WAIT_PREAMBLE --> ACCUMULATE: Preamble matched (Byte == 0xAA)
    WAIT_PREAMBLE --> WAIT_PREAMBLE: Ignore noise (Byte != 0xAA)
    ACCUMULATE --> ACCUMULATE: Accumulate bytes (rx_index under 16, dt within 20ms)
    ACCUMULATE --> WAIT_PREAMBLE: Timeout reset (dt over 20ms)
    ACCUMULATE --> PROCESS_FRAME: Frame captured (rx_index == 16)
    PROCESS_FRAME --> WAIT_PREAMBLE: Frame processed (rx_index = 0)
```

---

## 3. Hardware Bill of Materials & Wiring

### Bill of Materials
- **Sensor Node:** Arduino Nano clone (ATmega328P, 5 V logic, 16 MHz, 2 KB SRAM, 32 KB Flash)
- **Sensor:** DS18B20 waterproof digital temperature sensor (Maxim Integrated, 1-Wire protocol, 10-bit resolution)
- **Verifier:** STM32 Nucleo-L476RG (ARM Cortex-M4 with FPU, 80 MHz, 3.3 V logic, 128 KB SRAM, 1 MB Flash)
- **Resistors:**
  - $1 \times 4.7\text{ k}\Omega$ (DS18B20 1-Wire pull-up between D2 and +5 V — **mandatory**)
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
Arduino Nano GND    -----------------------------------------+-------------> Nucleo GND (CN6 Pin 6)

PC USB Connections
------------------
Arduino Nano USB  -----> PC (Programming & optional raw telemetry; unplug D1 during uploads)
Nucleo ST-Link USB-----> PC (Dual Virtual COM Port for logging, attack injection, and dashboard)
```

> [!IMPORTANT]
> **Hardware Configuration & Troubleshooting Notes:**
> 1. **DS18B20 Pull-Up Resistor:** An external $4.7\text{ k}\Omega$ pull-up resistor between the OneWire data line (D2) and +5V is **mandatory**. Without it, the OneWire bus floats and the sensor reports `-127.00 °C` (`DEVICE_DISCONNECTED_C`).
> 2. **STM32 Nucleo Jumper JP5:** Jumper `JP5` on the Nucleo board **must be capped on pins 1-2 (`U5V`)** to power the target MCU via ST-Link USB 5V. If `JP5` is missing, the target voltage drops to ~1.14V and ST-Link reports `target voltage may be too low for reliable debugging`.
> 3. **Nucleo Common Ground:** Connect the Arduino Nano GND to **Nucleo CN6 Pin 6 (GND)**. Do **NOT** connect to CN6 Pin 4 (which is the +3.3V rail), as doing so will dead-short the power rail and crash the verifier.
> 4. **Nano Upload Collisions:** Always disconnect the wire from pin **D1 (TX)** before flashing firmware to the Arduino Nano to avoid avrdude programming conflicts.

**Voltage Divider Calculation:**
$$V_{\text{out}} = 5.0\text{ V} \times \frac{2\text{ k}\Omega}{1\text{ k}\Omega + 2\text{ k}\Omega} = 3.333\text{ V}$$

This provides a safe, level-shifted signal for STM32 3.3 V logic (Nucleo pin PA10 is also 5 V tolerant).

---

## 4. Wire Protocol Specification

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

## 5. Getting Started: PlatformIO Build, Flash & Execution Guide

This repository is organized as a multi-root workspace containing two embedded PlatformIO targets (`nano_node` and `nucleo_verifier`) alongside a Python evaluation suite (`pc_tools`).

### Prerequisites
1. **VS Code** with the **PlatformIO IDE** extension installed, or PlatformIO Core CLI (`pio`).
2. **Python 3.9+** with virtual environment support.
3. **USB Drivers**:
   - CH340 / FTDI drivers for the Arduino Nano clone.
   - ST-LINK USB VCP drivers for the STM32 Nucleo-L476RG board.

---

### Option A: Using PlatformIO in VS Code (`secure_iot.code-workspace`)

1. Open VS Code, select **File -> Open Workspace from File...**, and choose `secure_iot.code-workspace`.
2. Open the **PlatformIO sidebar (alien icon)** -> **Project Tasks**:
   - **Flashing the Arduino Nano (`nano_node`):**
     1. **Important:** Temporarily unplug the jumper wire on pin **D1** (TX) to prevent avrdude upload collisions.
     2. Connect the Arduino Nano via USB.
     3. Under `nano_node`, click **Build**, then click **Upload**.
     4. Reconnect wire **D1** after the upload completes.
   - **Flashing the STM32 Nucleo (`nucleo_verifier`):**
     1. Connect the STM32 Nucleo via its ST-LINK USB port.
     2. Under `nucleo_verifier`, click **Build**, then click **Upload**.

---

### Option B: Using PlatformIO Core CLI (Terminal)

#### 1. Compile & Flash the Sensor Node (`nano_node`)
```bash
# Navigate to the sensor node project
cd nano_node

# Compile firmware
pio run

# Flash to Arduino Nano (disconnect D1 jumper before running)
pio run --target upload

# (Optional) Specify COM port if multiple devices are attached:
# pio run --target upload --upload-port COM4
```

#### 2. Compile & Flash the Verifier Node (`nucleo_verifier`)
```bash
# Navigate to the verifier project
cd ../nucleo_verifier

# Compile firmware
pio run

# Flash to STM32 Nucleo via ST-Link
pio run --target upload
```

---

## 6. Real-Time Telemetry & Security Evaluation Suite (`pc_tools`)

Ensure all serial monitors in VS Code or external terminals are **closed** so the serial ports are accessible to the Python tools.

### 1. Install Dependencies
```bash
cd pc_tools
python -m venv venv

# On Windows:
venv\Scripts\activate
# On Linux / macOS:
source venv/bin/activate

pip install -r requirements.txt
```

---

### 2. Live Cyberpunk Mission Control HUD (`dashboard.py`)

A full real-time mission control interface for live hardware monitoring, dynamic port detection, and interactive attack injection:

```bash
python dashboard.py
```
* Automatically opens in your browser at: **`http://127.0.0.1:8080`**

#### Key Features:
- **Live Physical Sensor HUD:** Large 54px glowing readout of authentic DS18B20 temperature, Fahrenheit conversion, min/max recorded tracking, and dynamic thermal status pills (`OPTIMAL ROOM ENVELOPE`, `ELEVATED TEMPERATURE`, `HIGH THERMAL ALARM`).
- **Real-Time Canvas Oscilloscope:** High-frequency trace of incoming temperature readings, annotated with color-coded attack detection markers in real time.
- **4-Stage Inline Verification Visualizer:** Visual stage-by-stage audit showing cycle counts and pass/drop indicators for Rate Limiter, HMAC-SHA256, Anti-Replay Window, and Plausibility Filter.
- **One-Click Attack Injection Console:** Interactive buttons to trigger live `TAMPER`, `REPLAY`, `FALSE DATA`, `FLOOD`, and `BENCHMARK ALL` vectors directly against the connected hardware.
- **Hardware Bus Watcher:** Automatically discovers, identifies, and connects to both the STM32 Nucleo Verifier (COM4) and Arduino Nano Sensor (COM3) using Server-Sent Events (SSE) and resilient fallback polling.

---

### 3. Standalone Adversarial Spoofing Attack Suite (`spoof_attack_demo.py`)

Demonstrates and verifies each attack vector sequentially against the live STM32 Nucleo hardware verifier:

```bash
python spoof_attack_demo.py
```

#### Automated Evaluation Vectors:
1. **Baseline Legitimate Packet:** Submits authentic packet with valid counter, real temperature, and correct HMAC tag -> Verified & Accepted in **~23,123 cycles**.
2. **Attack 1 (HMAC Tamper / Blind Spoofing):** Injects corrupted tag bytes without the 128-bit secret key -> Caught by **Stage 2 (HMAC-SHA256)** in **~22,889 cycles**.
3. **Attack 2 (Replay Spoofing Attack):** Re-transmits previously captured authentic frame -> Caught by **Stage 3 (Anti-Replay Window)** in **~22,993 cycles**.
4. **Attack 3 (Physical False-Data Jump):** Adversary with valid key injects physically impossible +35.0 °C jump in 50 ms -> Caught by **Stage 4 (Physical Plausibility)** in **~23,147 cycles**.
5. **Attack 4 (Out-of-Bounds Injection):** Injects validly signed +95.0 °C reading (exceeding +85.0 °C limit) -> Caught by **Stage 4 (Plausibility Range)** in **~23,025 cycles**.
6. **Attack 5 (Pre-Crypto DoS Flood Burst):** Bursts 15 high-speed packets -> **10/15 dropped by Stage 1 Rate Limiter in only 101 cycles (1.26 µs)**, saving 99.56% of cryptographic CPU overhead!

---

### 4. Large-Scale Benchmark & Academic Publication Pipeline

#### A. Automated Attack Benchmark (1,000 trials per attack)
```bash
python attacker.py --port COM4 --mode all --count 1000
```

#### B. Parse Metrics and CPU Cycle Savings
```bash
python evaluator.py
```
Outputs IEEE-formatted summary tables showing Detection Rate (%), False Positive Rate (%), average DWT cycle latency, and CPU cycle reduction.

#### C. Generate Publication Figures
```bash
python plot_results.py
```
Exports high-resolution publication charts to `pc_tools/results/`:
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
  `ca bd db 1d 4c 36 06 8d ad 0d 2e 63 a0 8d e8 01 b2 68 85 e8 af c6 99 80 80 e6 3e 26 fe 47 77 54`
- **Truncated 8-Byte Tag:** `ca bd db 1d 4c 36 06 8d`
- **Full 16-Byte Wire Packet:**
  `AA 01 00 00 00 01 09 60 CA BD DB 1D 4C 36 06 8D`

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

Empirical evaluation conducted on a physical **Arduino Nano (ATmega328P @ 16 MHz)** sensor node connected to a physical **STM32 Nucleo-L476RG (ARM Cortex-M4 @ 80 MHz)** verifier node via level-shifted hardware UART:

| Metric / Pipeline Stage | Measured Latency (Cycles / Time) | Empirical Detection Rate | Security Significance |
|:---|:---|:---|:---|
| **Stage 1: Pre-Crypto Rate Limiter** | **101 cycles (1.26 µs)** | **100.0% Mitigation** | Drops bursts > 5 pkt/s before hashing; saves **99.56% CPU overhead** |
| **Stage 2: HMAC-SHA256 Verification** | **~22,889 cycles (~286 µs)** | **100.0% Detection** | Constant-time tag evaluation; zero bit-flip leaks |
| **Stage 3: Anti-Replay Window** | **~22,993 cycles (~287 µs)** | **100.0% Detection** | Rejects duplicated and historical counters |
| **Stage 4: Physical Plausibility Gating**| **~23,123 cycles (~289 µs)** | **100.0% Detection** | Flags readings > +85.0 °C & sudden thermal shocks (> 5.0 °C/s) |
| **Stage 5: State Commit & Final Accept** | **~23,123 cycles (~289 µs)** | **100.0% Acceptance** | Monotonic state commit; passes authentic physical DS18B20 packets |
| **False Positive Rate (FPR)** | **0.00%** (N = 1,000+ trials) | **0.00%** | Zero false alarms on authentic ambient room telemetry (+26.25°C ~ +28.75°C) |
| **CPU Cycle Reduction on DoS Floods** | **99.56% reduction** | **~23,022 cycles saved/pkt** | Protects verifier from computational battery/CPU exhaustion |

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
