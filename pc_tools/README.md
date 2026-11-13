# PC Tools: IoT Attack Injection, Logging & Evaluation Suite

This directory contains the Python security evaluation framework for testing the **STM32 Nucleo-L476RG Verifier** against the **Arduino Nano Sensor Node**.

---

## 1. Installation

Install required dependencies:

```bash
pip install -r requirements.txt
```

---

## 2. Tools Overview

| Script | Purpose |
|---|---|
| `protocol.py` | 16-byte packet packing, unpacking, and HMAC-SHA256 reference |
| `attacker.py` | Injects Tamper, Replay, Flood, and False-Data attack vectors |
| `evaluator.py` | Computes True Positive Rate (TPR), cycle statistics, and CPU savings |
| `plot_results.py` | Generates publication-ready IEEE style figures (`fig_detection_rates.png`, etc.) |

---

## 3. Usage Workflows

### Step A: Capture Genuine Packets (Baseline)
Connect the Nucleo to your PC via USB and run:
```bash
python attacker.py --port COMx --mode capture --count 1000
```
*(Replace `COMx` with your Nucleo ST-Link virtual COM port, e.g., `COM3`)*

### Step B: Run Automated Attack Experiments (1,000 trials per attack)
```bash
python attacker.py --port COMx --mode all --count 1000
```
This tests:
1. **Tampering:** Random bit-flips in payload and HMAC $\rightarrow$ Flagged as `TAMPER`.
2. **Replay:** Stale counter injections $\rightarrow$ Flagged as `REPLAY`.
3. **Flood:** High-rate burst injection $\rightarrow$ Dropped as `FLOOD` before crypto.
4. **False-Data:** Impossible temperature jumps and out-of-range values $\rightarrow$ Flagged as `FALSE_DATA`.

### Step C: Evaluate Performance & Metrics
```bash
python evaluator.py
```
Outputs detection percentage, average DWT cycles, and CPU cycle savings.

### Step D: Generate Paper Figures
```bash
python plot_results.py
```
Outputs high-resolution IEEE charts to `pc_tools/results/`.
