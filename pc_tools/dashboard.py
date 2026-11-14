"""
SECURE-IOT // CYBERPUNK MISSION CONTROL & HARDWARE TELEMETRY HUD
Real-time hardware verification, dynamic port detection, and attack injection suite.
"""

import os
import sys
import time
import json
import random
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import urllib.parse

import serial
import serial.tools.list_ports as list_ports

# Import custom protocol definitions
from protocol import (
    build_packet,
    parse_packet,
    PROTOCOL_PACKET_SIZE,
    PROTOCOL_DEFAULT_NODE_ID,
    PRE_SHARED_KEY
)

# Configuration
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
BAUD_RATE = 115200

# Global State
active_serial = None
active_port_name = None
serial_lock = threading.Lock()
sse_clients = []
sse_lock = threading.Lock()

current_stats = {
    "clean_total": 0, "clean_def": 0,
    "tamper_total": 0, "tamper_def": 0,
    "replay_total": 0, "replay_def": 0,
    "flood_total": 0, "flood_def": 0,
    "false_total": 0, "false_def": 0,
    "total_processed": 0
}

latest_packet = {
    "verdict": "IDLE",
    "counter": 0,
    "temp": 24.0,
    "cycles": 0,
    "hex": "AA0100000001096055F153AD683E8D76"
}


# =============================================================================
# HARDWARE PORT DETECTOR
# =============================================================================

def detect_hardware():
    """Scans all system COM ports and identifies connected IoT nodes."""
    raw_ports = list(list_ports.comports())
    detected = {
        "nucleo": None,
        "nano": None,
        "all_ports": [],
        "active_port": active_port_name
    }

    for p in raw_ports:
        desc = (p.description or "").strip()
        hwid = (p.hwid or "").strip()
        desc_l = desc.lower()
        hwid_l = hwid.lower()
        vid = p.vid or 0
        pid = p.pid or 0

        port_data = {
            "device": p.device,
            "description": desc,
            "hwid": hwid,
            "vid": f"0x{vid:04X}" if vid else "N/A",
            "pid": f"0x{pid:04X}" if pid else "N/A",
            "board_type": "Generic Serial Device",
            "role": "Unknown",
            "arch": "Unknown",
            "memory": "Unknown"
        }

        # STM32 Nucleo Verifier (ST-Link V2.1 / V3)
        if vid == 0x0483 or "stlink" in desc_l or "nucleo" in desc_l or "stm32" in desc_l:
            port_data["board_type"] = "STM32 Nucleo-L476RG"
            port_data["role"] = "Verifier Node"
            port_data["arch"] = "ARM Cortex-M4 @ 80 MHz"
            port_data["memory"] = "1024 KB Flash / 96 KB SRAM"
            detected["nucleo"] = port_data

        # Arduino Nano Sensor Node (CH340 / FTDI / CP210x / ATmega328P)
        elif vid in [0x1A86, 0x0403, 0x10C4, 0x2341] or "ch340" in desc_l or "arduino" in desc_l or "nano" in desc_l:
            port_data["board_type"] = "Arduino Nano"
            port_data["role"] = "Sensor Node"
            port_data["arch"] = "AVR ATmega328P @ 16 MHz"
            port_data["memory"] = "32 KB Flash / 2 KB SRAM"
            detected["nano"] = port_data

        detected["all_ports"].append(port_data)

    return detected


# =============================================================================
# SERIAL READER & PROTOCOL DISPATCHER
# =============================================================================

def broadcast_event(data_dict):
    """Pushes an event to all connected web clients via Server-Sent Events."""
    msg = f"data: {json.dumps(data_dict)}\n\n"
    with sse_lock:
        dead_clients = []
        for client_wfile in sse_clients:
            try:
                client_wfile.write(msg.encode("utf-8"))
                client_wfile.flush()
            except Exception:
                dead_clients.append(client_wfile)
        for dead in dead_clients:
            if dead in sse_clients:
                sse_clients.remove(dead)

def send_verifier_command(cmd_str):
    """Sends ASCII control command to Nucleo firmware (e.g. CMD,RESET)."""
    global active_serial
    with serial_lock:
        if active_serial and active_serial.is_open:
            try:
                active_serial.write((cmd_str + "\n").encode("utf-8"))
                active_serial.flush()
                time.sleep(0.05)
                return True
            except Exception as e:
                print(f"[!] Error sending command '{cmd_str}': {e}")
    return False

def serial_worker(port_name):
    """Continuous background worker reading frames from the Nucleo/Nano."""
    global active_serial, active_port_name

    print(f"[*] Opening serial link to {port_name} @ {BAUD_RATE} baud...")
    try:
        ser = serial.Serial(port_name, baudrate=BAUD_RATE, timeout=0.5)
        time.sleep(1.5)  # Allow board reset to settle
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        
        with serial_lock:
            active_serial = ser
            active_port_name = port_name

        print(f"[+] Serial Link established on {port_name}!")
        # Re-arm rate limiting and reset state cleanly
        send_verifier_command("CMD,RESET")
        send_verifier_command("CMD,RATE_LIMIT,1")

    except Exception as e:
        print(f"[-] Failed to open {port_name}: {e}")
        with serial_lock:
            active_serial = None
            active_port_name = None
        return

    current_hex_cache = ""

    while True:
        with serial_lock:
            if not active_serial or not active_serial.is_open:
                break
            try:
                line = active_serial.readline().decode("utf-8", errors="ignore").strip()
            except Exception:
                break

        if not line:
            continue

        # Format 1: HEX,a01... (Raw wire frame)
        if line.startswith("HEX,"):
            current_hex_cache = line.split(",")[1].strip()

        # Format 2: LOG,reason,counter,temp,cycles
        elif line.startswith("LOG,"):
            parts = line.split(",")
            if len(parts) >= 5:
                try:
                    reason = parts[1]
                    counter = int(parts[2])
                    temp = float(parts[3])
                    cycles = int(parts[4])

                    packet_event = {
                        "verdict": reason,
                        "counter": counter,
                        "temp": temp,
                        "cycles": cycles,
                        "hex": current_hex_cache if current_hex_cache else "AA0100000001096055F153AD683E8D76"
                    }
                    latest_packet.update(packet_event)
                    broadcast_event(packet_event)
                    current_hex_cache = ""
                except ValueError:
                    pass


def connect_port(port_name):
    """Connects to a specific serial port in a background thread."""
    global active_serial, active_port_name
    disconnect_port()
    t = threading.Thread(target=serial_worker, args=(port_name,), daemon=True)
    t.start()

def disconnect_port():
    """Disconnects the active serial link."""
    global active_serial, active_port_name
    with serial_lock:
        if active_serial and active_serial.is_open:
            try:
                send_verifier_command("CMD,RESET")
                active_serial.close()
            except Exception:
                pass
        active_serial = None
        active_port_name = None


# =============================================================================
# ATTACK SIMULATION ENGINE (ASYNCHRONOUS)
# =============================================================================

def run_attack_task(mode, count):
    """Executes attack vectors asynchronously and broadcasts telemetry."""
    global active_serial
    if not active_serial or not active_serial.is_open:
        print("[!] Cannot execute attack: No active serial link.")
        return

    print(f"[*] Attacker Thread: Mode '{mode}', Count {count}...")

    if mode == "clean":
        send_verifier_command("CMD,RESET")
        send_verifier_command("CMD,RATE_LIMIT,0")
        base_ctr = 1000
        for i in range(count):
            base_ctr += 1
            sim_temp = 23.0 + 0.001 * i
            pkt = build_packet(PROTOCOL_DEFAULT_NODE_ID, base_ctr, sim_temp)
            with serial_lock:
                if active_serial and active_serial.is_open:
                    active_serial.write(pkt)
            time.sleep(0.015)
        send_verifier_command("CMD,RATE_LIMIT,1")

    elif mode == "tamper":
        send_verifier_command("CMD,RATE_LIMIT,0")
        base_ctr = 50000
        for i in range(count):
            base_ctr += 1
            pkt = bytearray(build_packet(PROTOCOL_DEFAULT_NODE_ID, base_ctr, 24.5))
            # Corrupt byte in HMAC tag (bytes 8..15)
            idx = random.randint(8, PROTOCOL_PACKET_SIZE - 1)
            pkt[idx] ^= random.randint(1, 255)
            with serial_lock:
                if active_serial and active_serial.is_open:
                    active_serial.write(bytes(pkt))
            time.sleep(0.015)
        send_verifier_command("CMD,RATE_LIMIT,1")

    elif mode == "replay":
        send_verifier_command("CMD,RATE_LIMIT,0")
        high_ctr = 100000
        # Seed legitimate baseline
        legit = build_packet(PROTOCOL_DEFAULT_NODE_ID, high_ctr, 24.0)
        with serial_lock:
            if active_serial and active_serial.is_open:
                active_serial.write(legit)
        time.sleep(0.05)

        for _ in range(count):
            stale_ctr = high_ctr - random.randint(1, 1000)
            pkt = build_packet(PROTOCOL_DEFAULT_NODE_ID, stale_ctr, 24.0)
            with serial_lock:
                if active_serial and active_serial.is_open:
                    active_serial.write(pkt)
            time.sleep(0.015)
        send_verifier_command("CMD,RATE_LIMIT,1")

    elif mode == "false_data":
        send_verifier_command("CMD,RATE_LIMIT,0")
        ctr = 300000
        legit = build_packet(PROTOCOL_DEFAULT_NODE_ID, ctr, 24.0)
        with serial_lock:
            if active_serial and active_serial.is_open:
                active_serial.write(legit)
        time.sleep(0.05)

        for i in range(count):
            ctr += 1
            spoofed_temp = 95.0 if i % 2 == 0 else (24.0 + 15.0)
            pkt = build_packet(PROTOCOL_DEFAULT_NODE_ID, ctr, spoofed_temp)
            with serial_lock:
                if active_serial and active_serial.is_open:
                    active_serial.write(pkt)
            time.sleep(0.015)
        send_verifier_command("CMD,RATE_LIMIT,1")

    elif mode == "flood":
        send_verifier_command("CMD,RESET")
        send_verifier_command("CMD,RATE_LIMIT,1")  # Rate limit actively enforced
        ctr = 200000
        packets = []
        for _ in range(count):
            ctr += 1
            packets.append(build_packet(PROTOCOL_DEFAULT_NODE_ID, ctr, 24.0))

        for pkt in packets:
            with serial_lock:
                if active_serial and active_serial.is_open:
                    active_serial.write(pkt)
            time.sleep(0.002)  # Burst at ~200 pkt/sec

    elif mode == "all":
        # Run entire multi-vector benchmark sequentially
        run_attack_task("clean", count)
        time.sleep(0.5)
        run_attack_task("tamper", count)
        time.sleep(0.5)
        run_attack_task("replay", count)
        time.sleep(0.5)
        run_attack_task("flood", count)
        time.sleep(0.5)
        run_attack_task("false_data", count)
        time.sleep(0.5)
        send_verifier_command("CMD,RESET")
        send_verifier_command("CMD,RATE_LIMIT,1")


# =============================================================================
# MULTI-THREADED HTTP & SSE SERVER
# =============================================================================

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence standard HTTP request logs to keep terminal cyber-clean
        return

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)

        # 1. Main Dashboard UI
        if url.path == "/" or url.path == "/index.html":
            html_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
            if os.path.exists(html_path):
                with open(html_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
            else:
                self.send_error(404, "dashboard.html not found.")

        # 2. Ports API
        elif url.path == "/api/ports":
            data = detect_hardware()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))

        # 3. Status API
        elif url.path == "/api/status":
            res = {
                "active_port": active_port_name,
                "latest_packet": latest_packet,
                "stats": current_stats
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))

        # 4. SSE Events Stream
        elif url.path == "/api/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            with sse_lock:
                sse_clients.append(self.wfile)

            # Keep connection alive until client disconnects
            try:
                while True:
                    time.sleep(1.0)
            except Exception:
                with sse_lock:
                    if self.wfile in sse_clients:
                        sse_clients.remove(self.wfile)

        else:
            self.send_error(404)

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            req_data = json.loads(body)
        except Exception:
            req_data = {}

        if url.path == "/api/connect":
            port = req_data.get("port")
            if port:
                connect_port(port)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        elif url.path == "/api/disconnect":
            disconnect_port()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        elif url.path == "/api/command":
            cmd = req_data.get("cmd", "")
            if cmd:
                send_verifier_command(cmd)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        elif url.path == "/api/attack":
            mode = req_data.get("mode", "clean")
            count = int(req_data.get("count", 10))
            threading.Thread(target=run_attack_task, args=(mode, count), daemon=True).start()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"queued"}')

        else:
            self.send_error(404)


# =============================================================================
# AUTO-DETECTION BACKGROUND WATCHER
# =============================================================================

def hardware_watcher_loop():
    """Periodically scans USB bus; automatically connects when Nucleo is found."""
    while True:
        try:
            if not active_port_name:
                hw = detect_hardware()
                if hw["nucleo"]:
                    print(f"\n[+] Auto-detected STM32 Nucleo on {hw['nucleo']['device']}! Connecting...")
                    connect_port(hw["nucleo"]["device"])
        except Exception as e:
            print(f"[!] Watcher error: {e}")
        time.sleep(2.0)


# =============================================================================
# MAIN ENTRYPOINT
# =============================================================================

CYBER_BANNER = r"""
  ___ ___ ___ _   _ ___ ___      ___ ___ _____ 
 / __| __/ __| | | | _ \ __|____|_ _/ _ \_   _|
 \__ \ _| (__| |_| |   / _|______| | (_) || |  
 |___/___\___|\___/|_|_\___|     |___\___/ |_|  
                                               
 >> TACTICAL TELEMETRY & ATTACK VERIFICATION HUD
 >> Dual-Node Embedded Security Platform
"""

def main():
    print(CYBER_BANNER)
    print("=" * 65)
    print(f"[*] Starting Cyberpunk Mission Control Server on http://{DEFAULT_HOST}:{DEFAULT_PORT}")
    print("[*] Launching Hardware Bus Watcher...")
    print("=" * 65)

    # Start Hardware auto-connection thread
    threading.Thread(target=hardware_watcher_loop, daemon=True).start()

    # Initial scan report
    hw = detect_hardware()
    if hw["nucleo"]:
        print(f"[*] Detected Verifier: {hw['nucleo']['board_type']} on {hw['nucleo']['device']}")
    if hw["nano"]:
        print(f"[*] Detected Sensor:   {hw['nano']['board_type']} on {hw['nano']['device']}")
    if not hw["nucleo"] and not hw["nano"]:
        print("[!] No boards currently detected on USB bus. Waiting for plug-in...")

    # Start HTTP & SSE Server
    server = ThreadedHTTPServer((DEFAULT_HOST, DEFAULT_PORT), DashboardHandler)
    url = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"

    # Auto-open browser
    try:
        webbrowser.open(url)
    except Exception:
        pass

    print(f"\n[+] Dashboard Live at: {url}")
    print("[+] Press Ctrl+C in this terminal to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Mission Control Server...")
        disconnect_port()
        server.server_close()
        print("[+] Offline.")

if __name__ == "__main__":
    main()
