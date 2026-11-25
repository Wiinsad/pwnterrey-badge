#include "WpsPinGen.h"
#include <string.h>
#include <algorithm>

// ── WPS Checksum ─────────────────────────────────────────────────────────────
// WPS spec: sum of digits weighted 3,1,3,1,3,1,3 mod 10, then 10 - sum mod 10
// (same as Luhn variant used for WPS)

uint32_t WpsPinGen::pinChecksum(uint32_t pin7) {
    uint32_t accum = 0;
    accum += 3 * ((pin7 / 10000000) % 10);
    accum +=     ((pin7 / 1000000)  % 10);
    accum += 3 * ((pin7 / 100000)   % 10);
    accum +=     ((pin7 / 10000)    % 10);
    accum += 3 * ((pin7 / 1000)     % 10);
    accum +=     ((pin7 / 100)      % 10);
    accum += 3 * ((pin7 / 10)       % 10);
    return (10 - (accum % 10)) % 10;
}

uint32_t WpsPinGen::makePin8(uint32_t pin7) {
    // pin7 is a 7-digit value (may start with 0)
    uint32_t base = pin7 % 10000000; // ensure max 7 digits
    return base * 10 + pinChecksum(base * 10); // shift left, compute checksum
}

String WpsPinGen::pinToString(uint32_t pin8) {
    char buf[9];
    snprintf(buf, sizeof(buf), "%08u", pin8 % 100000000);
    return String(buf);
}

// ── MAC-based PIN generators ─────────────────────────────────────────────────

uint32_t WpsPinGen::pinFromMAC24(const uint8_t mac[6]) {
    // NIC = last 3 bytes
    uint32_t nic = ((uint32_t)mac[3] << 16) |
                   ((uint32_t)mac[4] << 8)  |
                    (uint32_t)mac[5];
    uint32_t pin7 = nic % 10000000;
    return makePin8(pin7 * 10);
}

uint32_t WpsPinGen::pinFromMAC28(const uint8_t mac[6]) {
    // Last 28 bits
    uint32_t val = ((uint32_t)(mac[2] & 0x0F) << 24) |
                   ((uint32_t)mac[3] << 16) |
                   ((uint32_t)mac[4] << 8)  |
                    (uint32_t)mac[5];
    uint32_t pin7 = val % 10000000;
    return makePin8(pin7 * 10);
}

uint32_t WpsPinGen::pinFromMAC32(const uint8_t mac[6]) {
    uint64_t val = ((uint64_t)mac[2] << 24) |
                   ((uint64_t)mac[3] << 16) |
                   ((uint64_t)mac[4] << 8)  |
                    (uint64_t)mac[5];
    uint32_t pin7 = (uint32_t)(val % 10000000UL);
    return makePin8(pin7 * 10);
}

// D-Link algorithm (ported from WPSpin.pinDLink in Python)
uint32_t WpsPinGen::pinDLink(const uint8_t mac[6]) {
    uint32_t nic = ((uint32_t)mac[3] << 16) |
                   ((uint32_t)mac[4] << 8)  |
                    (uint32_t)mac[5];

    uint32_t pin = nic ^ 0x55AA55UL;
    pin ^= (((pin & 0xF) << 4)  |
            ((pin & 0xF) << 8)  |
            ((pin & 0xF) << 12) |
            ((pin & 0xF) << 16) |
            ((pin & 0xF) << 20));

    pin %= 10000000UL;
    if (pin < 1000000UL) {
        pin += ((pin % 9) * 1000000UL) + 1000000UL;
    }
    return makePin8(pin * 10);
}

uint32_t WpsPinGen::pinDLink1(const uint8_t mac[6]) {
    // Same as D-Link but with MAC NIC + 1
    uint8_t mac2[6];
    memcpy(mac2, mac, 6);
    // Increment NIC part (last 3 bytes, little-endian carry)
    uint32_t nic = ((uint32_t)mac2[3] << 16) |
                   ((uint32_t)mac2[4] << 8)  |
                    (uint32_t)mac2[5];
    nic = (nic + 1) & 0xFFFFFF;
    mac2[3] = (nic >> 16) & 0xFF;
    mac2[4] = (nic >> 8)  & 0xFF;
    mac2[5] =  nic        & 0xFF;
    return pinDLink(mac2);
}

// ASUS algorithm
uint32_t WpsPinGen::pinASUS(const uint8_t mac[6]) {
    const uint8_t *b = mac;
    char pin_str[8];
    // pin[i] = (b[i%6] + b[5]) % (10 - (i + b[1]+b[2]+b[3]+b[4]+b[5]) % 7)
    uint8_t sum_1to5 = b[1] + b[2] + b[3] + b[4] + b[5];
    for (int i = 0; i < 7; i++) {
        int divisor = 10 - (i + sum_1to5) % 7;
        if (divisor <= 0) divisor = 1;
        pin_str[i] = '0' + (char)((b[i % 6] + b[5]) % divisor);
    }
    pin_str[7] = '\0';

    uint32_t pin7 = 0;
    for (int i = 0; i < 7; i++) {
        pin7 = pin7 * 10 + (pin_str[i] - '0');
    }
    return makePin8(pin7 * 10);
}

// Airocon / Realtek algorithm
uint32_t WpsPinGen::pinAirocon(const uint8_t mac[6]) {
    const uint8_t *b = mac;
    uint32_t pin =
        ((b[0] + b[1]) % 10)             +
        (((b[5] + b[0]) % 10) * 10)      +
        (((b[4] + b[5]) % 10) * 100)     +
        (((b[3] + b[4]) % 10) * 1000)    +
        (((b[2] + b[3]) % 10) * 10000)   +
        (((b[1] + b[2]) % 10) * 100000)  +
        (((b[0] + b[1]) % 10) * 1000000);

    return makePin8(pin * 10);
}

// ── Aggregate ────────────────────────────────────────────────────────────────

std::vector<uint32_t> WpsPinGen::getAllPinsUint(const uint8_t mac[6]) {
    std::vector<uint32_t> pins;
    pins.push_back(pinFromMAC24(mac));
    pins.push_back(pinFromMAC28(mac));
    pins.push_back(pinFromMAC32(mac));
    pins.push_back(pinDLink(mac));
    pins.push_back(pinDLink1(mac));
    pins.push_back(pinASUS(mac));
    pins.push_back(pinAirocon(mac));

    // Deduplicate
    std::sort(pins.begin(), pins.end());
    pins.erase(std::unique(pins.begin(), pins.end()), pins.end());
    return pins;
}

std::vector<String> WpsPinGen::getAllPins(const uint8_t mac[6]) {
    std::vector<uint32_t> uint_pins = getAllPinsUint(mac);
    std::vector<String> str_pins;
    for (auto p : uint_pins) {
        str_pins.push_back(pinToString(p));
    }
    return str_pins;
}
