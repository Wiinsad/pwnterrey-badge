#include "WpsCrypto.h"
#include <Arduino.h>
#include <stdlib.h>
#include <string.h>

// ── WPS KDF label used in WPS spec ──────────────────────────────────────────
static const char WPS_KDF_LABEL[] = "Wi-Fi Easy and Secure Key Derivation";

// ── wpabuf helpers ───────────────────────────────────────────────────────────

struct wpabuf *WpsCrypto::bytesToWpabuf(const uint8_t *data, size_t len) {
    struct wpabuf *buf = (struct wpabuf *)malloc(sizeof(struct wpabuf) + len);
    if (!buf) return nullptr;
    buf->size  = len;
    buf->used  = len;
    buf->flags = 0;
    buf->buf   = (uint8_t *)(buf + 1); // data follows struct
    memcpy(buf->buf, data, len);
    return buf;
}

void WpsCrypto::freeWpabuf(struct wpabuf *b) {
    if (b) free(b);
}

// ── Constructor / Destructor ─────────────────────────────────────────────────

WpsCrypto::WpsCrypto()
    : _dh_priv(nullptr), _dh_publ(nullptr), _dh_ctx(nullptr) {
}

WpsCrypto::~WpsCrypto() {
    if (_dh_ctx) {
        dh5_free(_dh_ctx);
        _dh_ctx  = nullptr;
    }
    // Note: dh5_free is expected to free the priv/publ wpabufs too
    _dh_priv = nullptr;
    _dh_publ = nullptr;
}

// ── generateDHKeyPair ────────────────────────────────────────────────────────

bool WpsCrypto::generateDHKeyPair(uint8_t *out_pke) {
    if (!out_pke) return false;

    // Free any previous context
    if (_dh_ctx) {
        dh5_free(_dh_ctx);
        _dh_ctx  = nullptr;
        _dh_priv = nullptr;
        _dh_publ = nullptr;
    }

    _dh_priv = nullptr;
    _dh_publ = nullptr;

    _dh_ctx = dh5_init(&_dh_priv, &_dh_publ);
    if (!_dh_ctx) {
        Serial.println("[WpsCrypto] dh5_init failed");
        return false;
    }
    if (!_dh_publ || !_dh_publ->used) {
        Serial.println("[WpsCrypto] dh5_init returned empty public key");
        return false;
    }

    // Copy public key; zero-pad to DH_KEY_LEN if shorter
    size_t pub_len = _dh_publ->used;
    if (pub_len > (size_t)DH_KEY_LEN) pub_len = (size_t)DH_KEY_LEN;
    memset(out_pke, 0, DH_KEY_LEN);
    memcpy(out_pke + DH_KEY_LEN - pub_len, _dh_publ->buf, pub_len);

    return true;
}

// ── deriveSharedSecret ───────────────────────────────────────────────────────

bool WpsCrypto::deriveSharedSecret(const uint8_t *pkr, size_t pkr_len,
                                    uint8_t *out_secret, size_t &out_len) {
    if (!_dh_ctx || !_dh_priv) {
        Serial.println("[WpsCrypto] DH context not initialised – call generateDHKeyPair first");
        return false;
    }

    struct wpabuf *peer = bytesToWpabuf(pkr, pkr_len);
    if (!peer) return false;

    struct wpabuf *shared = dh5_derive_shared(_dh_ctx, peer, _dh_priv);
    freeWpabuf(peer);

    if (!shared) {
        Serial.println("[WpsCrypto] dh5_derive_shared failed");
        return false;
    }

    out_len = shared->used;
    if (out_len > (size_t)DH_KEY_LEN) out_len = (size_t)DH_KEY_LEN;
    memcpy(out_secret, shared->buf, out_len);
    freeWpabuf(shared);
    return true;
}

// ── deriveAuthKey ────────────────────────────────────────────────────────────
// WPS spec: KDK = HMAC-SHA-256(N1||N2||MAC, DHKey)
// But the standard derivation used in practice:
//   1. key_data = enrollee_nonce(16) || enrollee_mac(6) || registrar_nonce(16)
//   2. KDK = HMAC-SHA-256(dh_shared, key_data)
//   3. AuthKey = first 32 bytes from wps_kdf(KDK, "Wi-Fi Easy...")

bool WpsCrypto::deriveAuthKey(const uint8_t *dh_secret, size_t dh_len,
                               const uint8_t *enrollee_nonce,
                               const uint8_t *registrar_nonce,
                               const uint8_t *enrollee_mac,
                               uint8_t *out_authkey) {
    if (!dh_secret || !enrollee_nonce || !registrar_nonce ||
        !enrollee_mac || !out_authkey) return false;

    // Step 1: build key_data = enrollee_nonce || enrollee_mac || registrar_nonce
    uint8_t key_data[16 + 6 + 16];
    memcpy(key_data,      enrollee_nonce,  16);
    memcpy(key_data + 16, enrollee_mac,     6);
    memcpy(key_data + 22, registrar_nonce, 16);

    // Step 2: KDK = HMAC-SHA-256(dh_secret, key_data)
    uint8_t kdk[32];
    if (hmac_sha256(dh_secret, dh_len, key_data, sizeof(key_data), kdk) != 0) {
        Serial.println("[WpsCrypto] HMAC-SHA-256 for KDK failed");
        return false;
    }

    // Step 3: derive 3×32 = 96 bytes from KDF; first 32 = AuthKey
    uint8_t kdf_out[96];
    memset(kdf_out, 0, sizeof(kdf_out));
    if (wps_kdf(kdk, nullptr, 0, WPS_KDF_LABEL, kdf_out, sizeof(kdf_out)) != 0) {
        Serial.println("[WpsCrypto] wps_kdf failed");
        return false;
    }

    memcpy(out_authkey, kdf_out, 32); // AuthKey is first 32 bytes
    return true;
}

// ── computeEHash ─────────────────────────────────────────────────────────────
// E-Hash1 = HMAC-SHA-256(AuthKey, E-S1 || PSK1 || PKE || PKR)

bool WpsCrypto::computeEHash(const uint8_t *auth_key,
                              const uint8_t *e_snonce,
                              const uint8_t *psk,
                              const uint8_t *pke,
                              const uint8_t *pkr,
                              uint8_t *out_hash) {
    if (!auth_key || !e_snonce || !psk || !pke || !pkr || !out_hash) return false;

    // data = e_snonce(16) || psk(16) || pke(192) || pkr(192)
    const uint8_t *addr[4] = { e_snonce, psk, pke, pkr };
    size_t lens[4] = { 16, 16, (size_t)DH_KEY_LEN, (size_t)DH_KEY_LEN };

    if (hmac_sha256_vector(auth_key, AUTH_KEY_LEN, 4, addr, lens, out_hash) != 0) {
        Serial.println("[WpsCrypto] hmac_sha256_vector failed for E-Hash");
        return false;
    }
    return true;
}

// ── aesDecrypt ───────────────────────────────────────────────────────────────

bool WpsCrypto::aesDecrypt(const uint8_t *key, const uint8_t *iv,
                            uint8_t *data, size_t data_len) {
    if (!key || !iv || !data || data_len % 16 != 0) return false;
    // aes_128_cbc_decrypt modifies data in-place; needs writable iv copy
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    return aes_128_cbc_decrypt(key, iv_copy, data, data_len) == 0;
}

// ── derivePSK ────────────────────────────────────────────────────────────────
// PSK half = HMAC-SHA-256(AuthKey, PIN_half_string)  truncated to 16 bytes

bool WpsCrypto::derivePSK(const uint8_t *auth_key, const char *pin_half,
                           uint8_t *out_psk) {
    if (!auth_key || !pin_half || !out_psk) return false;
    uint8_t full_hash[32];
    if (hmac_sha256(auth_key, AUTH_KEY_LEN,
                    (const uint8_t *)pin_half, strlen(pin_half),
                    full_hash) != 0) return false;
    memcpy(out_psk, full_hash, 16);
    return true;
}
