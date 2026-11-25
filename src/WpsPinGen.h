#pragma once
#ifndef WpsPinGen_h
#define WpsPinGen_h

// WpsPinGen.h – WPS PIN generation algorithms
// Ported from Just_A_Shot_To_The_WiFi.py (class WPSpin)
// Supports: pin24, pin28, pin32, D-Link, ASUS, Airocon algorithms

#include <Arduino.h>
#include <vector>
#include <stdint.h>

class WpsPinGen {
public:
    // Compute WPS PIN checksum (8th digit from 7-digit base)
    static uint32_t pinChecksum(uint32_t pin7);

    // Build complete 8-digit PIN from 7-digit base + checksum
    static uint32_t makePin8(uint32_t pin7);

    // Format an 8-digit PIN as zero-padded string
    static String pinToString(uint32_t pin8);

    // ── Per-algorithm generators ─────────────────────────────────────────────

    // Last 3 bytes of MAC as PIN base (NIC part)
    static uint32_t pinFromMAC24(const uint8_t mac[6]);

    // Last 3.5 bytes (28 bits) of MAC as PIN base
    static uint32_t pinFromMAC28(const uint8_t mac[6]);

    // Last 4 bytes of MAC as PIN base (mod 10^8)
    static uint32_t pinFromMAC32(const uint8_t mac[6]);

    // D-Link algorithm
    static uint32_t pinDLink(const uint8_t mac[6]);

    // D-Link + 1 (some D-Link variants)
    static uint32_t pinDLink1(const uint8_t mac[6]);

    // ASUS algorithm
    static uint32_t pinASUS(const uint8_t mac[6]);

    // Airocon / Realtek algorithm
    static uint32_t pinAirocon(const uint8_t mac[6]);

    // ── Aggregate ────────────────────────────────────────────────────────────

    // Returns all candidate PINs (deduplicated, as 8-digit strings)
    static std::vector<String> getAllPins(const uint8_t mac[6]);

    // Same but as uint32_t values
    static std::vector<uint32_t> getAllPinsUint(const uint8_t mac[6]);
};

#endif // WpsPinGen_h
