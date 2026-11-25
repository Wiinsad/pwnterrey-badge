#pragma once
#ifndef WardriverStore_h
#define WardriverStore_h

#include "Arduino.h"

// Lightweight circular store for wardrive captures (RAM-only)
// Uses fixed char arrays to avoid heap fragmentation from 2000 String objects
struct WardriverEntry {
  char bssid[18];    // "AA:BB:CC:DD:EE:FF"
  char ssid[33];     // Max 32 chars + null
  char auth[20];     // "[WPA2_PSK]"
  char datetime[24]; // "2026-11-07 12:00:00"
  int16_t channel;    // int8_t overflows for 5GHz (ch>127: 149→-107)
  int8_t rssi;
  float lat;
  float lon;
  float alt;
  float accuracy;
  bool used;         // Slot occupied?
};

// 500 entries * ~114 bytes = ~57KB RAM — C5 has 242KB free heap, safe
#define WARDRIVE_STORE_MAX 200

class WardriverStore {
  public:
    WardriverStore();
    void add(String csv_line);
    void clear();
    int count();
    WardriverEntry* get(int index); // 0 = oldest
    String toJSON();
    String toCSV();
    bool active;
    int total;

  private:
    WardriverEntry entries[WARDRIVE_STORE_MAX];
    int head;
    void parseCSV(const String &line, WardriverEntry &e);
};

#endif
