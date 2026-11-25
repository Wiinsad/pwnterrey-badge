#pragma once
#ifndef WpsCrypto_h
#define WpsCrypto_h

// WpsCrypto.h – WPS cryptographic primitives for ESP32-C5 Pwnterrey Badge
// Wraps internal SDK symbols from libwpa_supplicant.a
// All SDK functions declared as extern "C" – no headers required.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// ── SDK extern declarations ──────────────────────────────────────────────────
extern "C" {

// Diffie-Hellman Group 5 (RFC 3526, 1536-bit MODP)
void  *dh5_init(struct wpabuf **priv, struct wpabuf **publ);
struct wpabuf *dh5_derive_shared(void *ctx, const struct wpabuf *peer_public,
                                  const struct wpabuf *own_private);
void   dh5_free(void *ctx);

// HMAC-SHA-256
int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t *mac);

int hmac_sha256_vector(const uint8_t *key, size_t key_len,
                       size_t num_elem,
                       const uint8_t * const *addr,
                       const size_t *len,
                       uint8_t *mac);

// SHA-256 (plain)
int sha256_vector(size_t num_elem,
                  const uint8_t * const *addr,
                  const size_t *len,
                  uint8_t *mac);

// WPS Key Derivation Function
int wps_kdf(const uint8_t *key, const uint8_t *label_prefix, size_t label_prefix_len,
            const char *label, uint8_t *res, size_t res_len);

// AES-128-CBC
int aes_128_cbc_encrypt(const uint8_t *key, const uint8_t *iv,
                         uint8_t *data, size_t data_len);
int aes_128_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                         uint8_t *data, size_t data_len);

} // extern "C"

// ── Forward-declare wpabuf (defined in wpa_supplicant internals) ─────────────
struct wpabuf {
    size_t   size;
    size_t   used;
    uint8_t *buf;
    unsigned int flags;
};

// ── WpsCrypto class ──────────────────────────────────────────────────────────
class WpsCrypto {
public:
    static const int DH_KEY_LEN  = 192; // 1536 bits / 8
    static const int AUTH_KEY_LEN = 32;
    static const int HASH_LEN    = 32;
    static const int AES_KEY_LEN = 16;

    WpsCrypto();
    ~WpsCrypto();

    // Generate DH keypair; stores private key internally.
    // Returns public key bytes (PKE) in out_pke (192 bytes), true on success.
    bool generateDHKeyPair(uint8_t *out_pke);

    // Derive shared DH secret from registrar public key (PKR, 192 bytes).
    // Returns shared secret in out_secret, sets out_len.
    bool deriveSharedSecret(const uint8_t *pkr, size_t pkr_len,
                             uint8_t *out_secret, size_t &out_len);

    // Derive AuthKey via WPS-KDF:
    //   key   = SHA-256(DH shared secret)
    //   label = "Wi-Fi Easy and Secure Key Derivation"
    //   data  = Enrollee-Nonce || Registrar-Nonce || Enrollee-MAC
    //   out   = first 32 bytes (AuthKey)
    bool deriveAuthKey(const uint8_t *dh_secret, size_t dh_len,
                       const uint8_t *enrollee_nonce,   // 16 bytes
                       const uint8_t *registrar_nonce,  // 16 bytes
                       const uint8_t *enrollee_mac,     // 6 bytes
                       uint8_t *out_authkey);

    // Compute E-Hash1 or E-Hash2:
    //   HMAC-SHA-256(AuthKey, E-S1 || PSK1 || PKE || PKR)
    bool computeEHash(const uint8_t *auth_key,     // 32 bytes
                      const uint8_t *e_snonce,     // 16 bytes (E-S1 or E-S2)
                      const uint8_t *psk,          // 16 bytes (PSK1 or PSK2)
                      const uint8_t *pke,          // 192 bytes
                      const uint8_t *pkr,          // 192 bytes
                      uint8_t *out_hash);          // 32 bytes

    // AES-128-CBC decrypt in-place (data must be multiple of 16 bytes)
    bool aesDecrypt(const uint8_t *key,   // 16 bytes
                    const uint8_t *iv,    // 16 bytes
                    uint8_t *data,
                    size_t data_len);

    // Helper: derive PSK half from PIN half
    // PSK = HMAC-SHA-256(AuthKey, PIN_half_string)
    bool derivePSK(const uint8_t *auth_key, const char *pin_half,
                   uint8_t *out_psk);

private:
    struct wpabuf *_dh_priv;  // private key (wpabuf from dh5_init)
    struct wpabuf *_dh_publ;  // public key  (wpabuf from dh5_init)
    void          *_dh_ctx;   // opaque DH context

    // Convert raw bytes to wpabuf for SDK calls
    struct wpabuf *bytesToWpabuf(const uint8_t *data, size_t len);
    void           freeWpabuf(struct wpabuf *b);
};

#endif // WpsCrypto_h
