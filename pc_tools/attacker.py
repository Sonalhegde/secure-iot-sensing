"""
Automated Security Assessment & Attack Suite for Nucleo Verifier.
Runs Baseline (Clean), Tamper, Replay, Flood, and False-Data Injection experiments.
"""
import argparse
import os
import sys
import time
import random
import serial
from protocol import (
    build_packet,
    parse_packet,
    PROTOCOL_PACKET_SIZE,
    PROTOCOL_DEFAULT_NODE_ID,
    PRE_SHARED_KEY
)

LOG_DIR = os.path.join(os.path.dirname(__file__), "results")
CAPTURE_DIR = os.path.join(os.path.dirname(__file__), "captures")
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(CAPTURE_DIR, exist_ok=True)

# Set deterministic seed for reproducible evaluations
random.seed(42)

def open_serial(port: str, baud: int = 115200, timeout: float = 1.0, max_retries: int = 3) -> serial.Serial:
    for attempt in range(1, max_retries + 1):
        try:
            ser = serial.Serial(port, baudrate=baud, timeout=timeout)
            time.sleep(2.0)  # Settle STM32 / USB VCP
            ser.reset_input_buffer()
            ser.reset_output_buffer()
            return ser
        except serial.SerialException as e:
            print(f"\n[WARNING] Attempt {attempt}/{max_retries}: Failed to open serial port {port}: {e}")
            print("          Port may be locked by PlatformIO Serial Monitor or another terminal.")
            if attempt < max_retries:
                input("          Please close any open serial monitors in VS Code (trash icon in terminal), then press Enter to retry...")
            else:
                print("[ERROR] Could not acquire serial port after multiple attempts. Exiting.")
                sys.exit(1)

def read_verifier_log(ser: serial.Serial, timeout_s: float = 1.0) -> dict:
    """Reads lines from Nucleo until a LOG line is captured or timeout occurs."""
    t_start = time.perf_counter()
    while time.perf_counter() - t_start < timeout_s:
        line = ser.readline().decode("utf-8", errors="ignore").strip()
        if line.startswith("LOG,"):
            # Format: LOG,reason,counter,temp,cycles
            parts = line.split(",")
            if len(parts) >= 5:
                try:
                    return {
                        "reason": parts[1],
                        "counter": int(parts[2]),
                        "temp": float(parts[3]),
                        "cycles": int(parts[4]),
                        "raw": line
                    }
                except ValueError:
                    pass
    return {"reason": "TIMEOUT", "counter": 0, "temp": 0.0, "cycles": 0, "raw": ""}

def run_capture(ser: serial.Serial, target_count: int = 1000):
    """Captures genuine packets passing through the Nucleo verifier."""
    print(f"[*] Starting genuine packet capture (Target: {target_count} packets)...")
    capture_file = os.path.join(CAPTURE_DIR, "genuine_packets.csv")
    raw_bin_file = os.path.join(CAPTURE_DIR, "genuine_packets.bin")

    collected = 0
    with open(capture_file, "w", encoding="utf-8") as f_csv, open(raw_bin_file, "wb") as f_bin:
        f_csv.write("index,counter,temp_c,hex\n")
        while collected < target_count:
            line = ser.readline().decode("utf-8", errors="ignore").strip()
            if line.startswith("HEX,"):
                hex_str = line.split(",")[1].strip()
                try:
                    raw_bytes = bytes.fromhex(hex_str)
                    if len(raw_bytes) == PROTOCOL_PACKET_SIZE:
                        pkt = parse_packet(raw_bytes)
                        f_bin.write(raw_bytes)
                        f_csv.write(f"{collected},{pkt['counter']},{pkt['temp_c']},{hex_str}\n")
                        f_csv.flush()
                        f_bin.flush()
                        collected += 1
                        if collected % 50 == 0 or collected == target_count:
                            print(f"    Captured {collected}/{target_count} packets...")
                except ValueError:
                    pass
    print(f"[+] Capture complete! Saved to {capture_file} and {raw_bin_file}")

def load_captured_packets() -> list:
    raw_bin_file = os.path.join(CAPTURE_DIR, "genuine_packets.bin")
    packets = []
    if os.path.exists(raw_bin_file):
        with open(raw_bin_file, "rb") as f:
            while True:
                chunk = f.read(PROTOCOL_PACKET_SIZE)
                if len(chunk) < PROTOCOL_PACKET_SIZE:
                    break
                packets.append(chunk)
    return packets

def run_clean_baseline(ser: serial.Serial, count: int = 1000, out_csv=None):
    """Evaluates False Positive Rate (FPR) using strictly legitimate, sequential packets."""
    print(f"[*] Running Clean Traffic Baseline ({count} trials)...")
    base_counter = 200000
    results = []

    for i in range(count):
        base_counter += 1
        # Realistic gradual ambient temperature (22.0 to 24.0 C)
        simulated_temp = 23.0 + 0.5 * (i % 20) / 20.0
        pkt = build_packet(PROTOCOL_DEFAULT_NODE_ID, base_counter, simulated_temp)

        ser.write(pkt)
        resp = read_verifier_log(ser)
        results.append(("CLEAN", resp["reason"], resp["cycles"]))
        if out_csv:
            out_csv.write(f"CLEAN,{i},{resp['reason']},{resp['cycles']}\n")
            out_csv.flush()

        if (i + 1) % 200 == 0:
            print(f"    Completed {i + 1}/{count} clean baseline packets...")
        time.sleep(0.01)

    accepted = sum(1 for r in results if r[1] == "ACCEPT")
    fp_count = count - accepted
    fp_rate = (fp_count / count) * 100.0
    print(f"[+] Clean Traffic Accepted: {accepted}/{count} (False Positive Rate: {fp_rate:.2f}%)")

def run_tamper_attack(ser: serial.Serial, count: int = 1000, out_csv=None):
    """Flipping random bits/bytes in genuine or synthetic packets."""
    print(f"[*] Running Tamper Attack Experiment ({count} trials)...")
    captured = load_captured_packets()
    base_counter = 300000

    results = []
    for i in range(count):
        if captured and i < len(captured):
            pkt_bytes = bytearray(captured[i % len(captured)])
        else:
            base_counter += 1
            pkt_bytes = bytearray(build_packet(PROTOCOL_DEFAULT_NODE_ID, base_counter, 24.5))

        # Corrupt 1 to 3 random bytes across payload and HMAC tag (skip 0xAA preamble at byte 0)
        corrupt_idx = random.randint(1, PROTOCOL_PACKET_SIZE - 1)
        pkt_bytes[corrupt_idx] ^= random.randint(1, 255)

        ser.write(bytes(pkt_bytes))
        resp = read_verifier_log(ser)
        results.append(("TAMPER_ATTACK", resp["reason"], resp["cycles"]))
        if out_csv:
            out_csv.write(f"TAMPER,{i},{resp['reason']},{resp['cycles']}\n")
            out_csv.flush()

        if (i + 1) % 200 == 0:
            print(f"    Completed {i + 1}/{count} tamper trials...")
        time.sleep(0.01)

    tamp_detected = sum(1 for r in results if r[1] == "TAMPER")
    print(f"[+] Tamper Detection Rate: {tamp_detected}/{count} ({tamp_detected/count*100:.2f}%)")

def run_replay_attack(ser: serial.Serial, count: int = 1000, out_csv=None):
    """Resending older, previously accepted packets with stale counters."""
    print(f"[*] Running Replay Attack Experiment ({count} trials)...")
    captured = load_captured_packets()

    # Seed verifier with a high counter
    high_counter = 600000
    legit_pkt = build_packet(PROTOCOL_DEFAULT_NODE_ID, high_counter, 24.0)
    ser.write(legit_pkt)
    time.sleep(0.05)
    _ = read_verifier_log(ser)

    results = []
    for i in range(count):
        if captured:
            # Replay genuine previously captured frame
            stale_pkt = captured[i % len(captured)]
        else:
            # Stale counter <= high_counter
            stale_counter = high_counter - random.randint(1, 1000)
            stale_pkt = build_packet(PROTOCOL_DEFAULT_NODE_ID, stale_counter, 24.0)

        ser.write(stale_pkt)
        resp = read_verifier_log(ser)
        results.append(("REPLAY_ATTACK", resp["reason"], resp["cycles"]))
        if out_csv:
            out_csv.write(f"REPLAY,{i},{resp['reason']},{resp['cycles']}\n")
            out_csv.flush()

        if (i + 1) % 200 == 0:
            print(f"    Completed {i + 1}/{count} replay trials...")
        time.sleep(0.01)

    replay_detected = sum(1 for r in results if r[1] == "REPLAY")
    print(f"[+] Replay Detection Rate: {replay_detected}/{count} ({replay_detected/count*100:.2f}%)")

def run_flood_attack(ser: serial.Serial, count: int = 1000, out_csv=None):
    """Flooding packets at high burst rate (>100 pkt/s) to evaluate pre-crypto rate limiting."""
    print(f"[*] Running Flood Attack Experiment ({count} packets at high burst rate)...")
    counter = 800000
    
    # Pre-build packet payloads to avoid loop serialization latency
    packets = []
    for _ in range(count):
        counter += 1
        packets.append(build_packet(PROTOCOL_DEFAULT_NODE_ID, counter, 24.0))

    t_start = time.perf_counter()
    results = []

    # Stream packets in rapid bursts
    for i, pkt in enumerate(packets):
        ser.write(pkt)
        resp = read_verifier_log(ser, timeout_s=0.02)
        results.append(("FLOOD_ATTACK", resp["reason"], resp["cycles"]))
        if out_csv:
            out_csv.write(f"FLOOD,{i},{resp['reason']},{resp['cycles']}\n")
            out_csv.flush()

        if (i + 1) % 200 == 0:
            print(f"    Completed {i + 1}/{count} flood packets...")

    t_elapsed = time.perf_counter() - t_start
    actual_rate = count / t_elapsed if t_elapsed > 0 else 0.0

    flood_dropped = sum(1 for r in results if r[1] == "FLOOD")
    print(f"[+] Flood Drop Rate: {flood_dropped}/{count} ({flood_dropped/count*100:.2f}%)")
    print(f"    Effective Attack Rate: {actual_rate:.1f} packets/second over wire")

def run_false_data_attack(ser: serial.Serial, count: int = 1000, out_csv=None):
    """Injecting validly HMAC-signed packets containing physically impossible jumps or extremes."""
    print(f"[*] Running False-Data (Physical Plausibility) Attack ({count} trials)...")
    counter = 900000
    legit_pkt = build_packet(PROTOCOL_DEFAULT_NODE_ID, counter, 24.0)
    ser.write(legit_pkt)
    time.sleep(0.05)
    _ = read_verifier_log(ser)

    results = []
    for i in range(count):
        counter += 1
        # Alternate between out-of-bounds (-20 C, 95 C) and impossible jumps (+15 C in 1s)
        if i % 2 == 0:
            spoofed_temp = 95.0  # Outside [-10, 85] bounds
        else:
            spoofed_temp = 24.0 + 15.0  # Sudden 15 C jump (exceeds 5 C/s limit)

        pkt = build_packet(PROTOCOL_DEFAULT_NODE_ID, counter, spoofed_temp)
        ser.write(pkt)
        resp = read_verifier_log(ser)
        results.append(("FALSE_DATA_ATTACK", resp["reason"], resp["cycles"]))
        if out_csv:
            out_csv.write(f"FALSE_DATA,{i},{resp['reason']},{resp['cycles']}\n")
            out_csv.flush()

        if (i + 1) % 200 == 0:
            print(f"    Completed {i + 1}/{count} false-data trials...")
        time.sleep(0.01)

    false_data_detected = sum(1 for r in results if r[1] == "FALSE_DATA")
    print(f"[+] False-Data Detection Rate: {false_data_detected}/{count} ({false_data_detected/count*100:.2f}%)")

def main():
    parser = argparse.ArgumentParser(description="IoT Security Verifier Attack & Evaluation Suite")
    parser.add_argument("--port", required=True, help="Nucleo ST-Link COM port (e.g., COM3, COM4)")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("--mode", choices=["clean", "capture", "tamper", "replay", "flood", "false_data", "all"], default="all")
    parser.add_argument("--count", type=int, default=1000, help="Number of packets per attack type (default: 1000)")
    args = parser.parse_args()

    ser = open_serial(args.port, args.baud)
    print(f"[+] Connected to Nucleo Verifier on {args.port} at {args.baud} baud.")

    if args.mode == "capture":
        run_capture(ser, args.count)
    elif args.mode == "clean":
        run_clean_baseline(ser, args.count)
    elif args.mode == "all":
        results_file = os.path.join(LOG_DIR, "all_experiments.csv")
        with open(results_file, "w", encoding="utf-8") as f_out:
            f_out.write("attack_type,iteration,verdict,cycles\n")
            run_clean_baseline(ser, args.count, f_out)
            time.sleep(1.0)
            run_tamper_attack(ser, args.count, f_out)
            time.sleep(1.0)
            run_replay_attack(ser, args.count, f_out)
            time.sleep(1.0)
            run_flood_attack(ser, args.count, f_out)
            time.sleep(1.0)
            run_false_data_attack(ser, args.count, f_out)
        print(f"\n[+] All experiments complete! Detailed logs stored in: {results_file}")
    else:
        results_file = os.path.join(LOG_DIR, f"{args.mode}_experiment.csv")
        with open(results_file, "w", encoding="utf-8") as f_out:
            f_out.write("attack_type,iteration,verdict,cycles\n")
            if args.mode == "tamper":
                run_tamper_attack(ser, args.count, f_out)
            elif args.mode == "replay":
                run_replay_attack(ser, args.count, f_out)
            elif args.mode == "flood":
                run_flood_attack(ser, args.count, f_out)
            elif args.mode == "false_data":
                run_false_data_attack(ser, args.count, f_out)

    ser.close()

if __name__ == "__main__":
    main()
