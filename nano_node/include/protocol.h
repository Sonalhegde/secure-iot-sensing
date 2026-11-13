#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

// --- Protocol Constants ---
#define PROTOCOL_PREAMBLE           0xAA
#define PROTOCOL_PACKET_SIZE        16
#define PROTOCOL_PAYLOAD_SIZE       7    // NodeID (1) + Counter (4) + Temp (2)
#define PROTOCOL_HMAC_SIZE          8    // Truncated 64-bit authentication tag
#define PROTOCOL_DEFAULT_NODE_ID    0x01

// Pre-Shared Secret Key (16 bytes = 128-bit key)
// Must be identical on Nano, Nucleo, and PC tools
static const uint8_t PRE_SHARED_KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

// Physical plausibility boundaries
#define PLAUSIBILITY_TEMP_MIN_RAW   -1000   // -10.00 C
#define PLAUSIBILITY_TEMP_MAX_RAW    8500   // +85.00 C
#define PLAUSIBILITY_MAX_DELTA_C_S          5.0f   // Max 5.0 C change per second
#define PLAUSIBILITY_MAX_DELTA_RAW_PER_SEC  500    // Max 5.00 C/s in raw centi-degrees (integer arithmetic)

// Rate limiting parameters (on Nucleo verifier)
#define RATE_LIMIT_MAX_PKT_PER_SEC   5      // Max 5 packets per 1000 ms window

// Inter-byte framing timeout (discard partial frames if silence exceeds this)
#define INTER_BYTE_TIMEOUT_MS        20

// Wire Packet Structure (16 bytes packed)
#pragma pack(push, 1)
typedef struct {
    uint8_t preamble;       // 0xAA
    uint8_t node_id;        // Node ID (0x01)
    uint8_t counter[4];     // 32-bit counter, Big-Endian
    uint8_t temp_raw[2];    // 16-bit signed temp (C * 100), Big-Endian
    uint8_t hmac[8];        // Truncated HMAC-SHA256
} Packet16;
#pragma pack(pop)

// Helper: Serialize payload fields into 7-byte buffer for HMAC computation
inline void protocol_serialize_payload(uint8_t node_id, uint32_t counter, int16_t temp_raw, uint8_t out_payload[PROTOCOL_PAYLOAD_SIZE]) {
    out_payload[0] = node_id;
    // Counter in Big-Endian (Network Byte Order)
    out_payload[1] = (uint8_t)((counter >> 24) & 0xFF);
    out_payload[2] = (uint8_t)((counter >> 16) & 0xFF);
    out_payload[3] = (uint8_t)((counter >> 8) & 0xFF);
    out_payload[4] = (uint8_t)(counter & 0xFF);
    // Temp in Big-Endian
    uint16_t utemp = (uint16_t)temp_raw;
    out_payload[5] = (uint8_t)((utemp >> 8) & 0xFF);
    out_payload[6] = (uint8_t)(utemp & 0xFF);
}

// Helper: Deserialize counter from byte array
inline uint32_t protocol_parse_counter(const uint8_t bytes[4]) {
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8)  |
           ((uint32_t)bytes[3]);
}

// Helper: Deserialize temperature from byte array
inline int16_t protocol_parse_temp(const uint8_t bytes[2]) {
    uint16_t utemp = ((uint16_t)bytes[0] << 8) | ((uint16_t)bytes[1]);
    return (int16_t)utemp;
}

#endif // PROTOCOL_H
