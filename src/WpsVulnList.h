#pragma once
#ifndef WpsVulnList_h
#define WpsVulnList_h

// WpsVulnList.h – Vulnerable WPS device lookup from SPIFFS
// Searches /vulnwsc.txt on-demand without loading into RAM.
// Safe for ESP32-C5 with limited heap.

#include <Arduino.h>

class WpsVulnList {
public:
    WpsVulnList();

    // Check SPIFFS for the file. Returns entry count (0 on failure).
    int  begin();

    // Search the file on-disk for modelName (case-insensitive substring).
    // Does NOT allocate large buffers — reads line by line.
    bool isVulnerable(const String &modelName);

    // Returns the matching line from the file, or empty string.
    String getVulnInfo(const String &modelName);

    // Number of entries counted at begin()
    int  count() const;

    bool isLoaded() const;

private:
    int     _count;
    bool    _available;  // file exists and is readable
};

#endif // WpsVulnList_h
