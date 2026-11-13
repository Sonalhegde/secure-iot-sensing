#include <Arduino.h>
#include "protocol.h"
#include "crypto_sha256.h"

// Hardware Serial link from Arduino Nano
// Nucleo D2 is PA10 (USART1_RX), PA9 is USART1_TX
HardwareSerial SerialNano(PA10, PA9);

// --- State Variables for Verification Pipeline ---
static uint32_t last_accepted_counter = 0;
static int16_t  last_accepted_temp_raw = 0;
static uint32_t last_accepted_time_ms = 0;
static bool     is_first_packet = true;

// Rate limiting state (sliding / epoch 1-second window)
static uint32_t rate_window_start_ms = 0;
static uint32_t packets_in_window = 0;

// Separate reception buffers for Hardware UART link and PC USB link
// Eliminates race conditions when injecting attacks over USB while Nano streams
static uint8_t nano_rx_buffer[PROTOCOL_PACKET_SIZE];
static uint8_t nano_rx_index = 0;
static uint32_t nano_last_byte_time_ms = 0;

static uint8_t usb_rx_buffer[PROTOCOL_PACKET_SIZE];
static uint8_t usb_rx_index = 0;
static uint32_t usb_last_byte_time_ms = 0;

// Initialize DWT Cycle Counter on ARM Cortex-M4
void init_dwt_cycle_counter() {
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

void setup() {
    // USB Virtual COM Port to PC for logging and attack testing
    Serial.begin(115200);
    while (!Serial && millis() < 2000) { }

    // Hardware link from Arduino Nano (via voltage divider)
    SerialNano.begin(115200);

    // Initialize high-precision cycle counter
    init_dwt_cycle_counter();

    Serial.println(F("# STM32 Nucleo-L476RG Verifier Online"));
    Serial.println(F("# Protocol: 16-byte HMAC-SHA256 Authenticated Sensing"));
    Serial.println(F("# Pipeline: RateLimit -> HMAC -> Counter -> Plausibility"));
    Serial.println(F("# CSV Format: LOG,reason,counter,temp,cycles"));
}

void process_frame(const Packet16 *pkt) {
    uint32_t t_start = DWT->CYCCNT;
    uint32_t now_ms = millis();

    // Parse packet fields safely
    uint32_t rx_counter = protocol_parse_counter(pkt->counter);
    int16_t  rx_temp_raw = protocol_parse_temp(pkt->temp_raw);
    float    temp_c = (float)rx_temp_raw / 100.0f;

    // =========================================================================
    // STEP 1: Rate Limiter (Drop flood packets BEFORE any cryptographic ops)
    // =========================================================================
    if (now_ms - rate_window_start_ms >= 1000) {
        rate_window_start_ms = now_ms;
        packets_in_window = 0;
    }
    packets_in_window++;

    if (packets_in_window > RATE_LIMIT_MAX_PKT_PER_SEC) {
        uint32_t cycles = DWT->CYCCNT - t_start;
        Serial.print(F("LOG,FLOOD,"));
        Serial.print(rx_counter);
        Serial.print(F(","));
        Serial.print(temp_c, 2);
        Serial.print(F(","));
        Serial.println(cycles);
        return; // Early exit: saved cryptographic CPU cost!
    }

    // =========================================================================
    // STEP 2: HMAC-SHA256 Verification (Tamper Detection)
    // =========================================================================
    // Payloads are contiguous at bytes 1..7 of the frame
    const uint8_t *payload_ptr = ((const uint8_t *)pkt) + 1;
    uint8_t computed_digest[SHA256_DIGEST_SIZE];

    uint32_t t_crypto_start = DWT->CYCCNT;
    hmac_sha256(PRE_SHARED_KEY, sizeof(PRE_SHARED_KEY), payload_ptr, PROTOCOL_PAYLOAD_SIZE, computed_digest);
    uint8_t tag_matches = hmac_constant_time_equal(computed_digest, pkt->hmac, PROTOCOL_HMAC_SIZE);
    uint32_t crypto_cycles = DWT->CYCCNT - t_crypto_start;

    if (!tag_matches) {
        Serial.print(F("LOG,TAMPER,"));
        Serial.print(rx_counter);
        Serial.print(F(","));
        Serial.print(temp_c, 2);
        Serial.print(F(","));
        Serial.println(crypto_cycles);
        return;
    }

    // =========================================================================
    // STEP 3: Counter Check (Replay Detection)
    // =========================================================================
    if (!is_first_packet) {
        if (rx_counter <= last_accepted_counter) {
            uint32_t cycles = DWT->CYCCNT - t_start;
            Serial.print(F("LOG,REPLAY,"));
            Serial.print(rx_counter);
            Serial.print(F(","));
            Serial.print(temp_c, 2);
            Serial.print(F(","));
            Serial.println(cycles);
            return;
        }
    }

    // =========================================================================
    // STEP 4: Physical Plausibility Check (False Data Detection)
    // =========================================================================
    // Check 4a: Absolute temperature range [-10.0 C to +85.0 C]
    if (rx_temp_raw < PLAUSIBILITY_TEMP_MIN_RAW || rx_temp_raw > PLAUSIBILITY_TEMP_MAX_RAW) {
        uint32_t cycles = DWT->CYCCNT - t_start;
        Serial.print(F("LOG,FALSE_DATA,"));
        Serial.print(rx_counter);
        Serial.print(F(","));
        Serial.print(temp_c, 2);
        Serial.print(F(","));
        Serial.println(cycles);
        return;
    }

    // Check 4b: Physical rate of change [Max 5.0 C/s = 500 raw units/s]
    // Uses integer cross-multiplication: delta_raw * 1000 > MAX_DELTA_RAW * dt_ms
    if (!is_first_packet) {
        uint32_t dt_ms = now_ms - last_accepted_time_ms;
        if (dt_ms == 0) dt_ms = 1; // guard against division by zero
        uint32_t delta_raw = (uint32_t)abs((int32_t)rx_temp_raw - (int32_t)last_accepted_temp_raw);

        if ((uint64_t)delta_raw * 1000ULL > (uint64_t)PLAUSIBILITY_MAX_DELTA_RAW_PER_SEC * dt_ms) {
            uint32_t cycles = DWT->CYCCNT - t_start;
            Serial.print(F("LOG,FALSE_DATA,"));
            Serial.print(rx_counter);
            Serial.print(F(","));
            Serial.print(temp_c, 2);
            Serial.print(F(","));
            Serial.println(cycles);
            return;
        }
    }

    // =========================================================================
    // STEP 5: Packet Valid - ACCEPT
    // =========================================================================
    last_accepted_counter = rx_counter;
    last_accepted_temp_raw = rx_temp_raw;
    last_accepted_time_ms = now_ms;
    is_first_packet = false;

    uint32_t total_cycles = DWT->CYCCNT - t_start;
    Serial.print(F("LOG,ACCEPT,"));
    Serial.print(rx_counter);
    Serial.print(F(","));
    Serial.print(temp_c, 2);
    Serial.print(F(","));
    Serial.println(total_cycles);

    // Also output the accepted packet in HEX format for PC capture tools
    Serial.print(F("HEX,"));
    const uint8_t *raw_bytes = (const uint8_t *)pkt;
    for (int i = 0; i < PROTOCOL_PACKET_SIZE; ++i) {
        if (raw_bytes[i] < 0x10) Serial.print('0');
        Serial.print(raw_bytes[i], HEX);
    }
    Serial.println();
}

void loop() {
    uint32_t now = millis();

    // Resync rule for Nano link: discard partial buffer if silence exceeds timeout
    if (nano_rx_index > 0 && (now - nano_last_byte_time_ms > INTER_BYTE_TIMEOUT_MS)) {
        nano_rx_index = 0;
    }

    // Resync rule for USB link
    if (usb_rx_index > 0 && (now - usb_last_byte_time_ms > INTER_BYTE_TIMEOUT_MS)) {
        usb_rx_index = 0;
    }

    // Read bytes from the Nano hardware UART link
    while (SerialNano.available() > 0) {
        uint8_t b = SerialNano.read();
        nano_last_byte_time_ms = millis();

        if (nano_rx_index == 0) {
            if (b == PROTOCOL_PREAMBLE) {
                nano_rx_buffer[0] = b;
                nano_rx_index = 1;
            }
        } else {
            nano_rx_buffer[nano_rx_index++] = b;
            if (nano_rx_index == PROTOCOL_PACKET_SIZE) {
                process_frame((const Packet16 *)nano_rx_buffer);
                nano_rx_index = 0;
            }
        }
    }

    // Read bytes from PC USB injection link (for attack script testing)
    while (Serial.available() > 0) {
        uint8_t b = Serial.read();
        usb_last_byte_time_ms = millis();

        if (usb_rx_index == 0) {
            if (b == PROTOCOL_PREAMBLE) {
                usb_rx_buffer[0] = b;
                usb_rx_index = 1;
            }
        } else {
            usb_rx_buffer[usb_rx_index++] = b;
            if (usb_rx_index == PROTOCOL_PACKET_SIZE) {
                process_frame((const Packet16 *)usb_rx_buffer);
                usb_rx_index = 0;
            }
        }
    }
}
