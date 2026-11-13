#ifndef CRYPTO_SHA256_H
#define CRYPTO_SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

// Standard SHA-256 functions
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);

// One-shot HMAC-SHA256 function
// key: pointer to pre-shared key
// key_len: length of key in bytes
// msg: pointer to input message buffer
// msg_len: length of message in bytes
// out_tag: output buffer for HMAC (at least 32 bytes for full, or truncated as needed)
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t out_digest[SHA256_DIGEST_SIZE]);

// Constant-time comparison for HMAC tags (mitigates timing side-channel attacks)
// Returns 1 if identical, 0 if different.
uint8_t hmac_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_SHA256_H
