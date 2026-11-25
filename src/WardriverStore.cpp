#include "WardriverStore.h"

WardriverStore::WardriverStore() : head(0), total(0), active(false) {
  memset(entries, 0, sizeof(entries));
}

void WardriverStore::parseCSV(const String &line, WardriverEntry &e) {
  // Parse WigleWifi CSV: BSSID,SSID,Auth,Datetime,Channel,RSSI,Lat,Lon,Alt,Accuracy,Type
  String tmp = line;
  tmp.trim();
  int idx = 0;
  int start = 0;
  String fields[11];
  for (int i = 0; i < 11 && start < (int)tmp.length(); i++) {
    int comma = tmp.indexOf(',', start);
    if (comma == -1) comma = tmp.length();
    fields[i] = tmp.substring(start, comma);
    start = comma + 1;
    idx = i;
  }
  fields[0].toCharArray(e.bssid, sizeof(e.bssid));
  fields[1].toCharArray(e.ssid, sizeof(e.ssid));
  fields[2].toCharArray(e.auth, sizeof(e.auth));
  fields[3].toCharArray(e.datetime, sizeof(e.datetime));
  e.channel = fields[4].toInt();
  e.rssi = fields[5].toInt();
  e.lat = fields[6].toFloat();
  e.lon = fields[7].toFloat();
  e.alt = fields[8].toFloat();
  e.accuracy = fields[9].toFloat();
  e.used = true;
}

void WardriverStore::add(String csv_line) {
  if (csv_line.length() < 10) return;
  parseCSV(csv_line, entries[head]);
  head = (head + 1) % WARDRIVE_STORE_MAX;
  if (total < WARDRIVE_STORE_MAX) total++;
}

void WardriverStore::clear() {
  memset(entries, 0, sizeof(entries));
  head = 0;
  total = 0;
}

int WardriverStore::count() { return total; }

WardriverEntry* WardriverStore::get(int index) {
  if (index < 0 || index >= total) return nullptr;
  int start = (total < WARDRIVE_STORE_MAX) ? 0 : head;
  int pos = (start + index) % WARDRIVE_STORE_MAX;
  return &entries[pos];
}

String WardriverStore::toJSON() {
  String json = "{\"active\":" + String(active ? "true" : "false") +
                ",\"count\":" + String(total) + ",\"entries\":[";
  bool first_entry = true;  // MED-4: proper comma logic
  for (int i = 0; i < total; i++) {
    WardriverEntry *e = get(i);
    if (!e || !e->used) continue;
    if (!first_entry) json += ",";  // MED-4: use first_entry flag not loop index
    first_entry = false;
    json += "{\"b\":\"" + String(e->bssid) + "\"";
    // Escape quotes in SSID
    String safe_ssid = String(e->ssid);
    safe_ssid.replace("\"", "\\\"");
    json += ",\"s\":\"" + safe_ssid + "\"";
    json += ",\"a\":\"" + String(e->auth) + "\"";
    json += ",\"ch\":" + String(e->channel);
    json += ",\"r\":" + String(e->rssi);
    json += ",\"la\":" + String(e->lat, 7);
    json += ",\"lo\":" + String(e->lon, 7);
    json += ",\"al\":" + String(e->alt, 1);
    json += ",\"ac\":" + String(e->accuracy, 1);
    json += ",\"t\":\"" + String(e->datetime) + "\"}";
  }
  json += "]}";
  return json;
}

String WardriverStore::toCSV() {
  String csv = "WigleWifi-1.4,appRelease=v1.2.1,model=PWNTERREY-C5,release=1.0,device=ESP32-C5,display=NONE,board=C5,brand=Pwnterrey\n";
  csv += "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n";
  for (int i = 0; i < total; i++) {
    WardriverEntry *e = get(i);
    if (!e || !e->used) continue;
    csv += String(e->bssid) + "," + String(e->ssid) + "," + String(e->auth) + ",";
    csv += String(e->datetime) + "," + String(e->channel) + "," + String(e->rssi) + ",";
    csv += String(e->lat, 7) + "," + String(e->lon, 7) + ",";
    csv += String(e->alt, 1) + "," + String(e->accuracy, 1) + ",WIFI\n";
  }
  return csv;
}
