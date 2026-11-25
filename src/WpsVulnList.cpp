#include "WpsVulnList.h"
#include "SPIFFS.h"

WpsVulnList::WpsVulnList()
    : _count(0), _available(false) {
}

int WpsVulnList::begin() {
    if (!SPIFFS.begin(true)) {
#ifndef MARAUDER_FLIPPER_C5
        Serial.println("[WpsVulnList] SPIFFS mount failed");
#endif
        return 0;
    }

    if (!SPIFFS.exists("/vulnwsc.txt")) {
#ifndef MARAUDER_FLIPPER_C5
        Serial.println("[WpsVulnList] /vulnwsc.txt not found in SPIFFS");
#endif
        return 0;
    }

    // Count lines without storing them
    File f = SPIFFS.open("/vulnwsc.txt", "r");
    if (!f) {
#ifndef MARAUDER_FLIPPER_C5
        Serial.println("[WpsVulnList] Cannot open /vulnwsc.txt");
#endif
        return 0;
    }

    _count = 0;
    while (f.available()) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (line.length() > 0) _count++;
    }
    f.close();

    _available = true;
#ifndef MARAUDER_FLIPPER_C5
    Serial.print("[WpsVulnList] Available: ");
    Serial.print(_count);
    Serial.println(" entries (on-disk, not loaded to RAM)");
#endif
    return _count;
}

bool WpsVulnList::isVulnerable(const String &modelName) {
    if (!_available || modelName.length() == 0) return false;

    File f = SPIFFS.open("/vulnwsc.txt", "r");
    if (!f) return false;

    String lower = modelName;
    lower.toLowerCase();

    char buf[128];
    while (f.available()) {
        int len = 0;
        while (f.available() && len < 127) {
            char c = f.read();
            if (c == '\n' || c == '\r') break;
            buf[len++] = c;
        }
        buf[len] = '\0';

        // Skip empty lines
        if (len == 0) continue;

        // Case-insensitive compare using stack buffer
        String entry(buf);
        entry.toLowerCase();
        if (entry.indexOf(lower) >= 0 || lower.indexOf(entry) >= 0) {
            f.close();
            return true;
        }
    }
    f.close();
    return false;
}

String WpsVulnList::getVulnInfo(const String &modelName) {
    if (!_available || modelName.length() == 0) return "";

    File f = SPIFFS.open("/vulnwsc.txt", "r");
    if (!f) return "";

    String lower = modelName;
    lower.toLowerCase();

    char buf[128];
    while (f.available()) {
        int len = 0;
        while (f.available() && len < 127) {
            char c = f.read();
            if (c == '\n' || c == '\r') break;
            buf[len++] = c;
        }
        buf[len] = '\0';
        if (len == 0) continue;

        String entry(buf);
        String entryLower = entry;
        entryLower.toLowerCase();
        if (entryLower.indexOf(lower) >= 0 || lower.indexOf(entryLower) >= 0) {
            f.close();
            return entry;
        }
    }
    f.close();
    return "";
}

int WpsVulnList::count() const {
    return _count;
}

bool WpsVulnList::isLoaded() const {
    return _available;
}
