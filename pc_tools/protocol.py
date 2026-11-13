"""
Protocol definitions and cryptographic helpers matching the embedded firmware.
"""
import struct
import hmac
import hashlib

PROTOCOL_PREAMBLE = 0xAA
PROTOCOL_PACKET_SIZE = 16
PROTOCOL_PAYLOAD_SIZE = 7
PROTOCOL_HMAC_SIZE = 8
PROTOCOL_DEFAULT_NODE_ID = 0x01

# 16-byte Pre-Shared Key (matches protocol.h on Nano & Nucleo)
PRE_SHARED_KEY = bytes([
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
])

def compute_hmac_tag(payload: bytes, key: bytes = PRE_SHARED_KEY) -> bytes:
    """Computes HMAC-SHA256 over 7-byte payload and returns the first 8 bytes."""
    full_digest = hmac.new(key, payload, hashlib.sha256).digest()
    return full_digest[:PROTOCOL_HMAC_SIZE]

def build_payload(node_id: int, counter: int, temp_c: float) -> bytes:
    """Serializes NodeID (1B), Counter (4B uint big-endian), Temp (2B int big-endian, C*100)."""
    temp_raw = int(round(temp_c * 100.0))
    return struct.pack(">BIh", node_id, counter, temp_raw)

def build_packet(node_id: int, counter: int, temp_c: float, key: bytes = PRE_SHARED_KEY) -> bytes:
    """Constructs a valid 16-byte authenticated sensor packet."""
    payload = build_payload(node_id, counter, temp_c)
    tag = compute_hmac_tag(payload, key)
    return bytes([PROTOCOL_PREAMBLE]) + payload + tag

def parse_packet(packet_bytes: bytes):
    """Parses a 16-byte packet into a dictionary."""
    if len(packet_bytes) != PROTOCOL_PACKET_SIZE:
        raise ValueError(f"Invalid packet length: {len(packet_bytes)} bytes (expected 16)")
    if packet_bytes[0] != PROTOCOL_PREAMBLE:
        raise ValueError(f"Invalid preamble: 0x{packet_bytes[0]:02X}")
    
    node_id, counter, temp_raw = struct.unpack(">BIh", packet_bytes[1:8])
    tag = packet_bytes[8:16]
    expected_tag = compute_hmac_tag(packet_bytes[1:8])
    is_valid_hmac = (tag == expected_tag)
    
    return {
        "node_id": node_id,
        "counter": counter,
        "temp_raw": temp_raw,
        "temp_c": temp_raw / 100.0,
        "hmac_tag": tag.hex(),
        "is_valid_hmac": is_valid_hmac,
        "raw_hex": packet_bytes.hex()
    }
