#pragma once

#ifndef EvilPortal_h
#define EvilPortal_h

#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>

#include "configs.h"
#include "settings.h"
#ifdef HAS_SCREEN
  #include "Display.h"
  #include <LinkedList.h>
#endif
#include "SDInterface.h"
#include "Buffer.h"
#include "lang_var.h"
#include <SPIFFS.h>   // Patch 6: serve portal.html from flash filesystem

extern Settings settings_obj;
extern SDInterface sd_obj;
#ifdef HAS_SCREEN
  extern Display display_obj;
#endif
extern Buffer buffer_obj; 

#define WAITING 0
#define GOOD 1
#define BAD 2

#define SET_HTML_CMD "sethtml="
#define SET_AP_CMD "setap="
#define RESET_CMD "reset"
#define START_CMD "start"
#define ACK_CMD "ack"
// 32 is the 802.11 maximum SSID length, +1 for the terminator. Was 30, which
// silently truncated any cloned SSID of 30+ characters: for an evil twin that
// means broadcasting a name that no longer matches the target, so victims never
// see the network they expect.
#define MAX_AP_NAME_SIZE 33
#define WIFI_SCAN_EVIL_PORTAL 30

extern char apName[MAX_AP_NAME_SIZE];
extern char index_html[MAX_HTML_SIZE];

struct ssid {
  String essid;
  uint8_t channel;
  uint8_t bssid[6];
  bool selected;
};

struct AccessPoint {
  String essid;
  uint8_t channel;
  uint8_t bssid[6];
  bool selected;
  LinkedList<char>* beacon;
  int8_t rssi;  // BUG-02 fix: was 'char' (unsigned on RISC-V) → negative values corrupted to 215 etc.
  LinkedList<uint8_t>* stations;
  uint8_t encryptionType; // H: Bug H — stored at scan time for /api/aps auth/open fields

  // WPS Information Elements (parsed from beacon/probe-response IE 0xDD OUI 00:50:F2:04)
  bool   wpsPresent;        // WPS IE found in beacon
  uint8_t wpsState;         // 0x01=not configured, 0x02=configured
  bool   wpsLocked;         // AP Setup Locked attribute
  String wpsManufacturer;   // attr 0x1021
  String wpsModelName;      // attr 0x1023
  String wpsModelNumber;    // attr 0x1024
  String wpsDeviceName;     // attr 0x1011
  bool   wpsVulnerable;     // found in vulnwsc.txt
};

// Captive portal handler moved to setupServer() logic

class EvilPortal {

  private:
    bool runServer;
    bool name_received;
    bool password_received;

    String user_name;
    String password;

    bool has_html;
    bool has_ap;

    DNSServer dnsServer;

    void (*resetFunction)(void) = 0;

    bool setHtml();
    bool setAP(LinkedList<ssid>* ssids, LinkedList<AccessPoint>* access_points);
    void setupServer();
    void setupManagementServer();   // management-mode routes: no DNS, no /get
    void startPortal(LinkedList<ssid>* ssids, LinkedList<AccessPoint>* access_points);
    void startAP();
    void sendToDisplay(String msg);
    String getSHA256(String data);

    // ── MANAGEMENT JOB STATE MACHINE ──────────────────────────
    // Firmware-side timing for web-triggered scans/attacks. The phone
    // cannot hold the AP connection while the radio is busy, so the
    // firmware owns start/stop timing and re-arms the management AP
    // afterwards; the phone reconnects and polls the final state.
    enum MgmtJobState : uint8_t {
      MGMT_JOB_IDLE = 0,
      MGMT_JOB_SCANNING,
      MGMT_JOB_ATTACK,
      MGMT_JOB_REARM
    };
    uint8_t  mgmt_job_state = MGMT_JOB_IDLE;
    String   mgmt_job_kind;            // e.g. "scan-ap", "attack-rickroll"
    uint32_t mgmt_job_t0 = 0;          // millis() when the job/state began
    uint32_t mgmt_job_duration_s = 0;  // 0 = indefinite (stop via /api/stop or reboot)
    bool     mgmt_scan_retried = false; // guards the single auto-retry when a scan returns 0/-2
    // Cross-cycle BSSID dedup for multi-cycle (timed) scans. Flat table on
    // purpose: LinkedList::get() returns AccessPoint BY VALUE, which copies
    // its String essid and churns the heap on every comparison — exactly what
    // must not happen while the WiFi driver is scanning.
    uint8_t  mgmt_scan_seen[64][6];
    uint8_t  mgmt_scan_seen_n = 0;
    String   mgmt_ssid;                // management AP SSID, kept for re-arm
    void   mgmtServiceJob();           // advance the state machine each loop
    String mgmtJobStateName();
    String mgmtStateJson();

    // ── PASSIVE HANDSHAKE CAPTURE (AP stays up) ────────────────
    struct hs_entry_t {
      uint8_t bssid[6];
      char ssid[33];
      uint8_t eapol_msgs;    // bitmask: 1=M1,2=M2,4=M3,8=M4
      bool has_pmkid;
      int8_t rssi;
      uint8_t ch;
    };
    #define MAX_HS_ENTRIES 32
    static hs_entry_t hs_list[MAX_HS_ENTRIES];
    static uint8_t hs_count;
    static bool hs_active;
    static bool hs_deauth;
    static void hsSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    static int hsFindOrAdd(const uint8_t* bssid);

    // ── PASSIVE MONITORS (deauth detector, probe logger, signal) ──
    struct deauth_event_t {
      uint8_t bssid[6];
      char ssid[33];
      uint16_t count;
      uint32_t last_ms;
      int8_t rssi;
    };
    #define MAX_DEAUTH_EVENTS 16
    static deauth_event_t deauth_list[MAX_DEAUTH_EVENTS];
    static uint8_t deauth_count;
    static bool deauth_monitor_active;

    struct probe_event_t {
      uint8_t mac[6];
      char ssid[33];
      int8_t rssi;
      uint32_t last_ms;
    };
    #define MAX_PROBE_EVENTS 32
    static probe_event_t probe_list[MAX_PROBE_EVENTS];
    static uint8_t probe_count;
    static bool probe_monitor_active;

    // Signal tracker
    static uint8_t sig_track_bssid[6];
    static bool sig_track_active;
    static int8_t sig_track_rssi;
    static uint32_t sig_track_last_ms;

    static void monitorSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);

    // ── OUTPUT CAPTURE RING BUFFER ─────────────────────────────
    #define WEB_OUTPUT_BUF_SIZE 4096
    static char _webOutBuf[WEB_OUTPUT_BUF_SIZE];
    static volatile uint16_t _webOutHead;  // MED-3: volatile to prevent register-caching across tasks
    static volatile uint16_t _webOutTail;  // MED-3: volatile
    static portMUX_TYPE _webOutLock;  // CRIT-5 fix: spinlock for atomic buffer operations

  public:
    bool rearmManagementAP(); // Bug1/3/8: public re-arm used by WiFiScan after scan jobs
    static void webOutWrite(const char* s) {
      // CRIT-5 fix: use portMUX spinlock for atomic read-modify-write
      portENTER_CRITICAL(&_webOutLock);
      while (*s) {
        _webOutBuf[_webOutHead] = *s++;
        _webOutHead = (_webOutHead + 1) % WEB_OUTPUT_BUF_SIZE;
        if (_webOutHead == _webOutTail)
          _webOutTail = (_webOutTail + 1) % WEB_OUTPUT_BUF_SIZE; // overwrite oldest
      }
      portEXIT_CRITICAL(&_webOutLock);
    }

    static String webOutDrain() {
      // F-13 fix: the previous version built the String one char at a time INSIDE the
      // critical section, so draining a full 4KB buffer performed thousands of heap
      // operations with interrupts disabled — and on ESP-IDF the allocator takes its own
      // lock, so that risks far worse than latency. Now the allocation happens outside
      // the lock and only two memcpy() calls run inside it.
      uint16_t h = _webOutHead, t = _webOutTail;
      if (h == t) return String("");
      uint16_t count = (h >= t) ? (uint16_t)(h - t)
                                : (uint16_t)(WEB_OUTPUT_BUF_SIZE - t + h);
      char* tmp = (char*)malloc((size_t)count + 1);
      if (tmp == nullptr) {
        // Out of memory: drop the buffered output rather than stall or corrupt state.
        portENTER_CRITICAL(&_webOutLock);
        _webOutTail = _webOutHead;
        portEXIT_CRITICAL(&_webOutLock);
        return String("");
      }
      portENTER_CRITICAL(&_webOutLock);
      // Re-read under the lock: the writer task may have advanced head since the snapshot.
      t = _webOutTail;
      h = _webOutHead;
      uint16_t n = (h >= t) ? (uint16_t)(h - t)
                            : (uint16_t)(WEB_OUTPUT_BUF_SIZE - t + h);
      if (n > count) n = count;  // never write past the allocation; the rest drains next call
      if ((uint32_t)t + n <= WEB_OUTPUT_BUF_SIZE) {
        memcpy(tmp, _webOutBuf + t, n);
      } else {
        uint16_t first = (uint16_t)(WEB_OUTPUT_BUF_SIZE - t);
        memcpy(tmp, _webOutBuf + t, first);
        memcpy(tmp + first, _webOutBuf, (size_t)(n - first));
      }
      _webOutTail = (uint16_t)(((uint32_t)t + n) % WEB_OUTPUT_BUF_SIZE);
      portEXIT_CRITICAL(&_webOutLock);
      tmp[n] = '\0';
      String result(tmp);
      free(tmp);
      return result;
    }

    EvilPortal();

    String target_html_name = "index.html";
    uint8_t selected_html_index = 0;

    bool using_serial_html;

    wifi_event_id_t _portal_event_id = 0;  // MED-6: track WiFi event handler ID for cleanup

    LinkedList<String>* html_files;

    String get_user_name();
    String get_password();
    void setup();
    bool begin(LinkedList<ssid>* ssids, LinkedList<AccessPoint>* access_points);
    void main(uint8_t scan_mode);
    void setHtmlFromSerial();

    // ── MANAGEMENT OPERATOR-CONTROL MODE ─────────────────────
    // Boot-time AP with WPA2 and whitelist-only /api/cmd. Fully separate
    // from the evil-portal USB flow: no setAP cloning, no DNS wildcard,
    // no captive redirects, no credential capture route.
    bool management_active = false;
    void startManagementPortal();
    void mainManagement();           // service web server every loop() pass

};

#endif