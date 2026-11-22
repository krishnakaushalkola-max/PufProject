// ESP32 256-bit SRAM PUF response + helper data kept in the ESP32's own flash (NVS).
//
// The PUF part is unchanged from puf_response_1.ino. New: the dashboard can send
// helper data over serial; it is saved in NVS and REPLACES any copy already there.
// Helper data is public (it reveals only 256-k bits of the response), so it is safe in flash.
// The key itself is never stored.
//
// Serial commands (one line each, 115200 baud):
//   HELPER <t> <helper_bits(256 x 0/1)> <salt_hex> <key_check_hex(64)> <info>   store / replace
//   HELPER?        print the stored helper data as HELPER_DATA ... (or HELPER_NONE)
//   HELPER_CLEAR   erase the stored helper data
// Replies: HELPER_OK stored|replaced|unchanged, HELPER_ERR <reason>, HELPER_DATA ..., HELPER_NONE

#include <Arduino.h>
#include <esp_system.h>
#include <Preferences.h>

#define PUF_BYTE_COUNT 32                    // 256 bits = 32 bytes
#define NVS_NAMESPACE  "pufhelper"
#define MAX_LINE       700

// RTC_NOINIT_ATTR: not zeroed by startup code, never written by this sketch.
// After a full power loss it holds the SRAM start-up state (the raw PUF response).
RTC_NOINIT_ATTR uint8_t puf_bytes[PUF_BYTE_COUNT];

struct Helper { int t; String bits, salt, check, info; };

static Preferences prefs;

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

/* ---------------- helper data in NVS ---------------- */

static bool loadHelper(Helper& h) {
  if (!prefs.begin(NVS_NAMESPACE, false)) return false;
  bool ok = prefs.getBool("ok", false);          // set only after every field was written
  if (ok) {
    h.t     = prefs.getInt("t", 0);
    h.bits  = prefs.getString("bits", "");
    h.salt  = prefs.getString("salt", "");
    h.check = prefs.getString("check", "");
    h.info  = prefs.getString("info", "");
  }
  prefs.end();
  return ok && h.bits.length() == 256;
}

// Returns "stored", "replaced", "unchanged", or nullptr on a flash write error.
static const char* saveHelper(const Helper& n) {
  Helper old;
  bool had = loadHelper(old);
  if (had && old.t == n.t && old.bits == n.bits && old.salt == n.salt &&
      old.check == n.check && old.info == n.info)
    return "unchanged";                          // skip the write, saves flash wear

  if (!prefs.begin(NVS_NAMESPACE, false)) return nullptr;
  prefs.putBool("ok", false);                    // a power cut mid-write leaves "no helper", never a mix
  bool good = prefs.putInt("t", n.t) > 0 &&
              prefs.putString("bits",  n.bits)  > 0 &&
              prefs.putString("salt",  n.salt)  > 0 &&
              prefs.putString("check", n.check) > 0 &&
              prefs.putString("info",  n.info)  > 0;
  if (good) prefs.putBool("ok", true);
  prefs.end();
  if (!good) return nullptr;
  return had ? "replaced" : "stored";
}

static void clearHelper() {
  if (prefs.begin(NVS_NAMESPACE, false)) { prefs.clear(); prefs.end(); }
}

/* ---------------- command parsing ---------------- */

static bool isBits(const String& s, size_t n) {
  if (s.length() != n) return false;
  for (size_t i = 0; i < n; i++) if (s[i] != '0' && s[i] != '1') return false;
  return true;
}
static bool isHex(const String& s, size_t minLen, size_t maxLen, bool even) {
  if (s.length() < minLen || s.length() > maxLen || (even && (s.length() & 1))) return false;
  for (size_t i = 0; i < s.length(); i++) if (!isxdigit((unsigned char)s[i])) return false;
  return true;
}
static String nextToken(String& s) {             // pops the first space-separated token
  s.trim();
  int p = s.indexOf(' ');
  String tok = (p < 0) ? s : s.substring(0, p);
  s = (p < 0) ? String("") : s.substring(p + 1);
  return tok;
}

static void printStatus() {
  Helper h;
  Serial.print(F("PUF buffer @ 0x")); Serial.println((uint32_t)puf_bytes, HEX);
  if (loadHelper(h)) {
    Serial.print(F("Helper data in ESP: stored (t=")); Serial.print(h.t);
    Serial.print(F(", check=")); Serial.print(h.check.substring(0, 8)); Serial.println(F("...)"));
  } else {
    Serial.println(F("Helper data in ESP: none"));
  }
}

static void handleLine(String line) {
  line.trim();
  if (line.length() == 0) return;

  if (line == "HELPER?") {
    Helper h;
    if (!loadHelper(h)) { Serial.println(F("HELPER_NONE")); return; }
    Serial.print(F("HELPER_DATA ")); Serial.print(h.t);
    Serial.print(' '); Serial.print(h.bits);
    Serial.print(' '); Serial.print(h.salt);
    Serial.print(' '); Serial.print(h.check);
    Serial.print(' '); Serial.println(h.info);
    return;
  }
  if (line == "HELPER_CLEAR") { clearHelper(); Serial.println(F("HELPER_OK cleared")); return; }

  if (line.startsWith("HELPER ")) {
    String rest = line.substring(7);
    Helper h;
    String ts = nextToken(rest);
    h.t     = ts.toInt();
    h.bits  = nextToken(rest);
    h.salt  = nextToken(rest);
    h.check = nextToken(rest);
    h.info  = rest; h.info.trim();               // info is the remainder of the line

    if (h.t < 1 || h.t > 64)                    { Serial.println(F("HELPER_ERR bad t")); return; }
    if (!isBits(h.bits, 256))                   { Serial.println(F("HELPER_ERR helper_bits must be 256 x 0/1")); return; }
    if (!isHex(h.salt, 2, 64, true))            { Serial.println(F("HELPER_ERR bad salt")); return; }
    if (!isHex(h.check, 64, 64, false))         { Serial.println(F("HELPER_ERR bad key_check")); return; }
    if (h.info.length() < 1 || h.info.length() > 120) { Serial.println(F("HELPER_ERR bad info")); return; }

    const char* r = saveHelper(h);
    if (!r) Serial.println(F("HELPER_ERR flash write failed"));
    else { Serial.print(F("HELPER_OK ")); Serial.println(r); }
  }
}

static String rx;
static bool rxOverflow = false;

static void pollSerial() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') {
      if (rxOverflow) Serial.println(F("HELPER_ERR line too long"));
      else handleLine(rx);
      rx = ""; rxOverflow = false;
    } else if (c != '\r') {
      if (rx.length() < MAX_LINE) rx += c; else rxOverflow = true;
    }
  }
}

static uint32_t lastPrint = 0;

void setup() {
  Serial.setRxBufferSize(1024);                  // a HELPER line is ~400 bytes
  Serial.begin(115200);
  printResponse();                               // first print, right at boot
  printStatus();
  lastPrint = millis();
}

void loop() {
  pollSerial();                                  // never blocks, so commands are never dropped
  // Buffer is never modified, so re-prints are the same response; lets the host
  // catch it if the serial port only reappears a few seconds after power-up.
  if (millis() - lastPrint >= 2000) {
    lastPrint = millis();
    printResponse();
  }
  delay(2);
}
