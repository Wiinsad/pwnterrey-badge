#include "SerialMirror.h"
// On ESP32-C5 with USB-JTAG CDC (HWCDCSerial / /dev/ttyACM0):
// HWCDCSerial is defined in HWCDC.h when ARDUINO_USB_CDC_ON_BOOT=1.
// We build with CDCOnBoot=cdc to enable it; also forward-declare here
// as a safety net for translation units that may not have the flag.
#ifdef ARDUINO_USB_CDC_ON_BOOT
#  if ARDUINO_USB_CDC_ON_BOOT
#    include <HWCDC.h>
     extern HWCDC HWCDCSerial;
#    define SERIAL_HW HWCDCSerial
#  else
     extern HardwareSerial Serial0;
#    define SERIAL_HW Serial0
#  endif
#else
  extern HardwareSerial Serial0;
# define SERIAL_HW Serial0
#endif

// Static LogBuffer storage
char SerialMirror::_logBuf[SERIAL_MIRROR_BUF_SIZE];
volatile uint16_t SerialMirror::_logHead = 0;
volatile uint16_t SerialMirror::_logTail = 0;

SerialMirror serial_mirror;

void SerialMirror::begin(unsigned long baud) {
  SERIAL_HW.begin(baud);
#ifdef MARAUDER_FLIPPER_C5
  // On C5 with CDCOnBoot (HWCDC USB), the default tx_timeout_ms=100ms causes
  // Serial.println() to block for 100ms per byte when no USB host is connected.
  // This stalls setup() for many seconds, preventing the management AP from starting.
  // Setting timeout=0 makes all writes non-blocking when no host is consuming CDC TX.
  SERIAL_HW.setTxTimeoutMs(0);
#endif
}
int SerialMirror::available() { return SERIAL_HW.available(); }
int SerialMirror::read() { return SERIAL_HW.read(); }
int SerialMirror::peek() { return SERIAL_HW.peek(); }
int SerialMirror::availableForWrite() { return SERIAL_HW.availableForWrite(); }
void SerialMirror::flush() { SERIAL_HW.flush(); }

void SerialMirror::logAppend(uint8_t c) {
  _logBuf[_logHead] = (char)c;
  _logHead = (_logHead + 1) % SERIAL_MIRROR_BUF_SIZE;
  if (_logHead == _logTail)
    _logTail = (_logTail + 1) % SERIAL_MIRROR_BUF_SIZE; // overwrite oldest
}

size_t SerialMirror::write(uint8_t c) {
  size_t n = SERIAL_HW.write(c);
  logAppend(c);
  return n;
}

size_t SerialMirror::write(const uint8_t* buf, size_t size) {
  size_t n = SERIAL_HW.write(buf, size);
  for (size_t i = 0; i < n; i++)
    logAppend(buf[i]);
  return n;
}

void SerialMirror::telemetry(const char* line) {
  size_t size = strlen(line);
  // Do not stall the main loop when no USB host is draining CDC TX.
  // Mirror directly once so /api/poll keeps receiving channel telemetry.
  for (size_t i = 0; i < size; ++i) logAppend((uint8_t)line[i]);
  if (SERIAL_HW.availableForWrite() >= (int)size)
    SERIAL_HW.write((const uint8_t*)line, size);
}

String SerialMirror::logDrain() {
  String out = "";
  while (_logTail != _logHead) {
    out += _logBuf[_logTail];
    _logTail = (_logTail + 1) % SERIAL_MIRROR_BUF_SIZE;
  }
  return out;
}
