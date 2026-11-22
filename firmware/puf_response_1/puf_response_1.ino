#include <Arduino.h>
#include <esp_system.h>

// 256 bits = 32 bytes
#define PUF_BYTE_COUNT 32

// RTC_NOINIT_ATTR: not zeroed by startup code, never written by this sketch.
// After a full power loss it holds the SRAM start-up state (the raw PUF response).
RTC_NOINIT_ATTR uint8_t puf_bytes[PUF_BYTE_COUNT];

static const char* resetReason() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON:  return "POWERON";
    case ESP_RST_BROWNOUT: return "BROWNOUT";
    case ESP_RST_EXT:      return "EXT";
    case ESP_RST_SW:       return "SW";
    case ESP_RST_PANIC:    return "PANIC";
    case ESP_RST_INT_WDT:  return "INT_WDT";
    case ESP_RST_TASK_WDT: return "TASK_WDT";
    case ESP_RST_WDT:      return "WDT";
    case ESP_RST_DEEPSLEEP:return "DEEPSLEEP";
    default:               return "UNKNOWN";
  }
}

static void printResponse() {
  Serial.println(F("\n--- ESP32 256-bit SRAM PUF Response ---"));
  Serial.print(F("Reset Reason:     "));
  Serial.println(resetReason());

  Serial.print(F("Binary (256-bit): "));
  for (uint8_t i = 0; i < PUF_BYTE_COUNT; i++)
    for (int8_t bit = 7; bit >= 0; bit--) Serial.print((puf_bytes[i] >> bit) & 0x01);
  Serial.println();

  Serial.print(F("Hex (256-bit):    0x"));
  for (uint8_t i = 0; i < PUF_BYTE_COUNT; i++) {
    if (puf_bytes[i] < 0x10) Serial.print('0');
    Serial.print(puf_bytes[i], HEX);
  }
  Serial.println();

  uint16_t hw = 0;
  for (uint8_t i = 0; i < PUF_BYTE_COUNT; i++) hw += __builtin_popcount(puf_bytes[i]);
  Serial.print(F("Hamming Weight:   "));
  Serial.print(hw);
  Serial.println(F(" / 256 bits"));
}

void setup() {
  Serial.begin(115200);
  printResponse();            // first print, right at boot
}

void loop() {
  // Buffer is never modified, so re-prints are the same response; lets the host
  // catch it if the serial port only reappears a few seconds after power-up.
  delay(2000);
  printResponse();
}
