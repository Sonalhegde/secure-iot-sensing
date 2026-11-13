"""
Evaluator script: Analyzes experimental logs, computes detection performance,
computes cycle savings, and formats IEEEtran paper-ready tables.
"""
import os
import pandas as pd
import numpy as np

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
LOG_FILE = os.path.join(RESULTS_DIR, "all_experiments.csv")

def analyze_results(log_path=LOG_FILE):
    if not os.path.exists(log_path):
        print(f"[!] Log file not found at {log_path}. Please run attacker.py first.")
        return

    df = pd.read_csv(log_path)
    print("\n" + "="*75)
    print("      EXPERIMENTAL RESULTS & ATTACK DETECTION PERFORMANCE")
    print("="*75)

    # Clean traffic baseline check
    clean_sub = df[df["attack_type"] == "CLEAN"]
    if not clean_sub.empty:
        total_clean = len(clean_sub)
        accepted = (clean_sub["verdict"] == "ACCEPT").sum()
        false_positives = total_clean - accepted
        fp_rate = (false_positives / total_clean) * 100.0
        print(f"[*] Baseline Clean Traffic:")
        print(f"    - Packets Evaluated:     {total_clean}")
        print(f"    - Legitimate Accepted:   {accepted}")
        print(f"    - False Positives (FP):  {false_positives}")
        print(f"    - False Positive Rate:   {fp_rate:.2f}%")
        print("-" * 75)

    attack_mapping = {
        "TAMPER": "TAMPER",
        "REPLAY": "REPLAY",
        "FLOOD": "FLOOD",
        "FALSE_DATA": "FALSE_DATA"
    }

    summary = []
    for attack, target_verdict in attack_mapping.items():
        subset = df[df["attack_type"] == attack]
        total = len(subset)
        if total == 0:
            continue
        detected = (subset["verdict"] == target_verdict).sum()
        detection_rate = (detected / total) * 100.0
        
        # Valid cycle counts (>0 and not timeout)
        valid_cycles = subset[subset["cycles"] > 0]["cycles"]
        avg_cycles = valid_cycles.mean() if not valid_cycles.empty else 0
        std_cycles = valid_cycles.std() if not valid_cycles.empty else 0

        summary.append({
            "Attack Vector": attack,
            "Total Injected": total,
            "Detected": detected,
            "Detection Rate (%)": f"{detection_rate:.2f}%",
            "Avg Cycles (80MHz)": f"{avg_cycles:.1f} ± {std_cycles:.1f}",
            "Latency (us)": f"{(avg_cycles / 80.0):.2f} us"
        })

    if summary:
        summary_df = pd.DataFrame(summary)
        print(summary_df.to_string(index=False))

    print("\n" + "="*75)
    print("          CPU CYCLE SAVINGS (FLOOD VS CRYPTO VERIFICATION)")
    print("="*75)
    flood_cycles = df[df["verdict"] == "FLOOD"]["cycles"]
    tamper_cycles = df[df["verdict"] == "TAMPER"]["cycles"]

    if not flood_cycles.empty and not tamper_cycles.empty:
        f_mean = flood_cycles.mean()
        t_mean = tamper_cycles.mean()
        savings_cycles = t_mean - f_mean
        savings_pct = (savings_cycles / t_mean) * 100.0
        print(f"  * Flood Drop Cycles (pre-crypto):   {f_mean:.1f} cycles ({(f_mean/80.0):.2f} us)")
        print(f"  * Isolated HMAC-SHA256 Cycles:      {t_mean:.1f} cycles ({(t_mean/80.0):.2f} us)")
        print(f"  * CPU Cycles Saved per Packet:      {savings_cycles:.1f} cycles ({savings_pct:.2f}% reduction!)")
    print("="*75 + "\n")

if __name__ == "__main__":
    analyze_results()
