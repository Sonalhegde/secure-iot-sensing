#include <Arduino.h>
#include <EEPROM.h>
#include <OneWire.h>
#include <DallasTemperature.h>
#include "protocol.h"
#include "crypto_sha256.h"

// --- Hardware Pin Definitions ---
#define ONE_WIRE_BUS        2   // DS18B20 data line connected to Nano D2
#define EEPROM_COUNTER_ADDR 0   // 4 bytes for uint32_t counter

// --- Configuration ---
// 1 = Normal authenticated operation with real DS18B20
// 0 = Synthetic payload generator for throughput / flood tests
#define MODE_REAL_SENSOR        1
#define ENABLE_BOOT_BENCHMARK   0   // Set 1 to print ASCII benchmark (disable when connected to Nucleo link)

// --- Setup OneWire and DallasTemperature ---
OneWire oneWire(ONE_WIRE_BUS);
DallasTemperature sensors(&oneWire);

// --- Runtime State ---
static uint32_t current_counter = 0;
static uint32_t packet_index = 0;
static unsigned long last_tx_time = 0;

// Benchmark function: measures average HMAC-SHA256 time over 100 runs
void run_hmac_benchmark() {
    uint8_t sample_payload[PROTOCOL_PAYLOAD_SIZE] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x09, 0xC4};
    uint8_t digest[SHA256_DIGEST_SIZE];

    // Warm-up run
    hmac_sha256(PRE_SHARED_KEY, sizeof(PRE_SHARED_KEY), sample_payload, sizeof(sample_payload), digest);

    unsigned long t_start = micros();
    const int RUNS = 100;
    for (int i = 0; i < RUNS; ++i) {
        hmac_sha256(PRE_SHARED_KEY, sizeof(PRE_SHARED_KEY), sample_payload, sizeof(sample_payload), digest);
    }
    unsigned long t_total = micros() - t_start;
    float avg_us = (float)t_total / RUNS;

#if ENABLE_BOOT_BENCHMARK
    Serial.print(F("# BENCHMARK: Nano ATmega328P HMAC-SHA256 avg time: "));
    Serial.print(avg_us, 2);
    Serial.println(F(" us"));
#else
    (void)avg_us;
#endif
}

void setup() {
    // Initialize Hardware Serial at 115200 baud
    Serial.begin(115200);

    // Initialize EEPROM counter with anti-replay protection
    uint32_t stored_val = 0;
    EEPROM.get(EEPROM_COUNTER_ADDR, stored_val);
    
    // Check if EEPROM is fresh/erased (0xFFFFFFFF)
    if (stored_val == 0xFFFFFFFF || stored_val == 0) {
        current_counter = 100;
    } else {
        // Jump ahead by 100 so a reboot is never mistaken for a replay attack
        current_counter = stored_val + 100;
    }
    EEPROM.put(EEPROM_COUNTER_ADDR, current_counter);

    // Initialize DS18B20 temperature sensor
    sensors.begin();
    sensors.setResolution(10); // 10-bit resolution = ~187.5ms conversion time
    sensors.setWaitForConversion(true);

    // Run crypto benchmark on startup
    run_hmac_benchmark();
    
    // Allow brief settle time
    delay(500);
}

void loop() {
    unsigned long now = millis();

    // Transmit 1 packet per second (1 Hz)
    if (now - last_tx_time >= 1000) {
        last_tx_time = now;

        int16_t temp_raw = 0;

#if MODE_REAL_SENSOR
        // Request temperature conversion from DS18B20
        sensors.requestTemperatures();
        float temp_c = sensors.getTempCByIndex(0);

        // Check for sensor disconnect (-127.0 C or DEVICE_DISCONNECTED_C) or hardware fault
        if (temp_c == DEVICE_DISCONNECTED_C || temp_c < -55.0f || temp_c > 125.0f) {
            // Drop transmission on sensor failure: do not fabricate false readings
            return;
        }

        // DS18B20 power-on reset state check (+85.00 C scratchpad default)
        // If 85.0 C occurs as the very first read, wait for valid reading
        if (temp_c == 85.0f && packet_index == 0) {
            return;
        }

        temp_raw = (int16_t)roundf(temp_c * 100.0f);
#else
        // Synthetic mode: gentle oscillation around 24.0 C
        static float synthetic_c = 24.0f;
        temp_raw = (int16_t)(synthetic_c * 100.0f);
#endif

        // Increment monotonically increasing counter
        current_counter++;
        packet_index++;

        // Persist to EEPROM every 100 packets to preserve EEPROM write endurance
        if (packet_index % 100 == 0) {
            EEPROM.put(EEPROM_COUNTER_ADDR, current_counter);
        }

        // Build 7-byte authenticated payload: [NodeID 1B][Counter 4B][Temp 2B]
        uint8_t payload[PROTOCOL_PAYLOAD_SIZE];
        protocol_serialize_payload(PROTOCOL_DEFAULT_NODE_ID, current_counter, temp_raw, payload);

        // Compute HMAC-SHA256 over the 7-byte payload
        uint8_t full_digest[SHA256_DIGEST_SIZE];
        hmac_sha256(PRE_SHARED_KEY, sizeof(PRE_SHARED_KEY), payload, PROTOCOL_PAYLOAD_SIZE, full_digest);

        // Assemble full 16-byte wire packet
        Packet16 packet;
        packet.preamble = PROTOCOL_PREAMBLE;
        packet.node_id = PROTOCOL_DEFAULT_NODE_ID;
        packet.counter[0] = payload[1];
        packet.counter[1] = payload[2];
        packet.counter[2] = payload[3];
        packet.counter[3] = payload[4];
        packet.temp_raw[0] = payload[5];
        packet.temp_raw[1] = payload[6];

        // Truncate HMAC to first 8 bytes (64-bit tag)
        for (int i = 0; i < PROTOCOL_HMAC_SIZE; ++i) {
            packet.hmac[i] = full_digest[i];
        }

        // Transmit the 16 bytes over UART (D1 TX -> Voltage Divider -> Nucleo PA10 RX)
        Serial.write((const uint8_t *)&packet, sizeof(packet));
        Serial.flush();
    }
}
