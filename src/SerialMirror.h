#pragma once

#ifndef SerialMirror_h
#define SerialMirror_h

#include <Arduino.h>

// SerialMirror: wraps the USB CDC serial (HWCDCSerial) so every byte written
// by any sketch Serial.print/println/printf is also appended to a bounded
// 4 KiB ring buffer (LogBuffer) that the management AP serves via /api/poll.
// The write path performs no heap/String allocation, so it is safe to call
// from WiFi event callbacks and other restricted contexts.
class SerialMirror : public Stream {
  public:
    void begin(unsigned long baud);          // forward to HWCDCSerial
    int available() override;                // Stream input side
    int read() override;
    int peek() override;
    int availableForWrite() override;
    void flush() override;
    // readString/readStringUntil/printf and all print/println variants are
    // inherited from Stream/Print and route through write() below.

    size_t write(uint8_t c) override;        // forward + mirror
    size_t write(const uint8_t* buf, size_t size) override;
    using Print::write;

    // Periodic status: always mirror, write USB only if space is available.
    void telemetry(const char* line);
    static String logDrain();                // empty the LogBuffer (caller side)

  private:
    #define SERIAL_MIRROR_BUF_SIZE 4096
    static char _logBuf[SERIAL_MIRROR_BUF_SIZE];
    static volatile uint16_t _logHead;
    static volatile uint16_t _logTail;
    static void logAppend(uint8_t c);        // bounded, no allocation
};

extern SerialMirror serial_mirror;

// Redirect every sketch `Serial` use to the mirror. The Arduino core defined
// `Serial` as HWCDCSerial in HardwareSerial.h (included via Arduino.h above);
// configs.h includes this header before any other sketch header uses Serial.
#undef Serial
#define Serial serial_mirror

#endif
