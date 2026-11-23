// ESP32 WROOM-32: SRAM-PUF device authentication, ONE firmware for both phases.
//
//  mode "capture" (default): prints the 256-bit SRAM start-up response (for enrolment), no Wi-Fi.
//  mode "run"              : at every power-up the response is copied FIRST, the key is rebuilt from the
//                            helper data stored in this chip's flash (BCH error correction + HKDF-SHA-256),
//                            then Wi-Fi + cloud: poll, and when the cloud asks, HMAC-sign its nonce.
//                            The response and the key are never printed in run mode.
//
// Nothing is hard-coded. Everything is set by serial commands (sent by the PUF dashboard through the DevKit
// bridge) and kept in flash (NVS):
//   HELPER <t> <256 bits> <salt_hex> <key_check_hex> <info>   store / replace helper data
//   HELPER?   HELPER_CLEAR
//   CFG ssid <name> | CFG pass <password> | CFG server http://<ip>:5000 | CFG device <id> | CFG mode capture|run
//   CFG?      CFG_CLEAR
// Settings take effect at the next power-up.

#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <esp_system.h>
#include "mbedtls/md.h"

#define PUF_BYTE_COUNT 32                       // 256 bits
#define MAX_LINE       700
#define POLL_MS        2000
#define NONCE_BUDGET_MS 25000
#define TELEMETRY_MS   5000                     // how often a reading is sent (after authentication)
#define TOKEN_RENEW_MS 780000UL                 // session token lasts 15 min on the server; renew at 13 min
#define AUTH_RETRY_MS  15000

// Never written by this sketch. After a full power loss it holds the SRAM start-up state (the PUF response).
RTC_NOINIT_ATTR uint8_t puf_bytes[PUF_BYTE_COUNT];
static uint8_t pufCopy[PUF_BYTE_COUNT];         // run mode: copied at the very start of setup()

struct Helper { int t; String bits, salt, check, info; };
struct Config { String mode, ssid, pass, server, device; bool registered = false; };

static Preferences prefs;
static Config cfg;
static bool runMode = false;
static bool keyOK = false;
static uint8_t KEY[32];
static String token;                            // session token from the nonce/HMAC handshake
static uint32_t tokenAt = 0;
static int pufErrors = -1;                      // bit errors corrected at boot (a PUF health figure)

/* ======================= BCH decoder (matches the dashboard's ExtBCH) ======================= */
// BEGIN BCH
static uint8_t gfExp[510], gfLog[256];
static void gfInit() {
  int x = 1;
  for (int i = 0; i < 255; i++) { gfExp[i] = gfExp[i + 255] = (uint8_t)x; gfLog[x] = (uint8_t)i; x <<= 1; if (x & 0x100) x ^= 0x11D; }
}
static inline uint8_t gfMul(uint8_t a, uint8_t b) { return (a && b) ? gfExp[gfLog[a] + gfLog[b]] : 0; }
static inline uint8_t gfDiv(uint8_t a, uint8_t b) { return a ? gfExp[(gfLog[a] - gfLog[b] + 255) % 255] : 0; }

// r: 256 received bits (0/1). cw: corrected 256-bit codeword. Returns number of corrected bits, or -1 if more than t.
static int extDecode(const uint8_t* r, int t, uint8_t* cw) {
  const int n = 255;
  if (t < 1 || 2 * t > 64) return -1;
  uint8_t S[64];
  bool any = false;
  for (int j = 1; j <= 2 * t; j++) {
    uint8_t s = 0;
    for (int i = 0; i < n; i++) if (r[i]) s ^= gfExp[(i * j) % n];
    S[j - 1] = s; if (s) any = true;
  }
  memcpy(cw, r, 255);
  int errors = 0;
  if (any) {
    uint8_t C[160], B[160], T[160];
    memset(C, 0, sizeof C); memset(B, 0, sizeof B);
    int clen = 1, blen = 1, L = 0, m = 1;
    uint8_t b = 1; C[0] = 1; B[0] = 1;
    for (int q = 0; q < 2 * t; q++) {
      uint8_t d = S[q];
      for (int i = 1; i <= L; i++) if (q - i >= 0) d ^= gfMul(i < clen ? C[i] : 0, S[q - i]);
      if (!d) { m++; continue; }
      memcpy(T, C, sizeof T);
      int tlen = clen;
      uint8_t f = gfDiv(d, b);
      while (clen < blen + m) { if (clen >= 150) return -1; C[clen++] = 0; }
      for (int i = 0; i < blen; i++) C[i + m] ^= gfMul(f, B[i]);
      if (2 * L <= q) { L = q + 1 - L; memcpy(B, T, sizeof B); blen = tlen; b = d; m = 1; }
      else m++;
    }
    if (L > t) return -1;
    int found = 0;
    for (int i = 0; i < n; i++) {
      uint8_t v = 0;
      for (int k = 0; k <= L; k++) {
        uint8_t ck = k < clen ? C[k] : 0;
        if (ck) v ^= gfMul(ck, gfExp[((-i * k) % n + n) % n]);
      }
      if (!v) { cw[i] ^= 1; found++; }
    }
    if (found != L) return -1;
    errors = L;
  }
  uint8_t p = 0;
  for (int i = 0; i < 255; i++) p ^= cw[i];
  cw[255] = p;
  int tot = errors + (p != r[255] ? 1 : 0);
  return tot > t ? -1 : tot;
}
// END BCH

/* ======================= helper data + config in NVS ======================= */
static bool loadHelper(Helper& h) {
  if (!prefs.begin("pufhelper", false)) return false;
  bool ok = prefs.getBool("ok", false);
  if (ok) {
    h.t = prefs.getInt("t", 0);
    h.bits = prefs.getString("bits", ""); h.salt = prefs.getString("salt", "");
    h.check = prefs.getString("check", ""); h.info = prefs.getString("info", "");
  }
  prefs.end();
  return ok && h.bits.length() == 256;
}
static const char* saveHelper(const Helper& n) {         // "stored" | "replaced" | "unchanged" | nullptr (flash error)
  Helper old;
  bool had = loadHelper(old);
  if (had && old.t == n.t && old.bits == n.bits && old.salt == n.salt && old.check == n.check && old.info == n.info) return "unchanged";
  if (!prefs.begin("pufhelper", false)) return nullptr;
  prefs.putBool("ok", false);                            // a power cut mid-write leaves "no helper data", never a mix
  bool good = prefs.putInt("t", n.t) > 0 && prefs.putString("bits", n.bits) > 0 && prefs.putString("salt", n.salt) > 0 &&
              prefs.putString("check", n.check) > 0 && prefs.putString("info", n.info) > 0;
  if (good) prefs.putBool("ok", true);
  prefs.end();
  return good ? (had ? "replaced" : "stored") : nullptr;
}
static void clearHelper() { if (prefs.begin("pufhelper", false)) { prefs.clear(); prefs.end(); } }

static Config loadCfg() {
  Config c;
  if (prefs.begin("pufcfg", false)) {
    c.mode = prefs.getString("mode", "capture"); c.ssid = prefs.getString("ssid", ""); c.pass = prefs.getString("pass", "");
    c.server = prefs.getString("server", "");    c.device = prefs.getString("device", "");
    c.registered = prefs.getBool("reg", false);
    prefs.end();
  } else c.mode = "capture";
  return c;
}
static void setReg(bool v) {                                   // "registered in the cloud" flag (Wi-Fi is allowed only when set)
  if (prefs.begin("pufcfg", false)) { prefs.putBool("reg", v); prefs.end(); }
  cfg.registered = v;
}
static const char* setCfg(const String& n, const String& v) {   // nullptr = ok, otherwise the error text
  if (n == "registered") {
    if (v != "0" && v != "1") return "registered must be 0 or 1";
    if (!prefs.begin("pufcfg", false)) return "flash error";
    prefs.putBool("reg", v == "1"); prefs.end();
    return nullptr;
  }
  if (n == "mode") { if (v != "capture" && v != "run") return "mode must be capture or run"; }
  else if (n == "ssid") { if (v.length() < 1 || v.length() > 32) return "ssid must be 1-32 characters"; }
  else if (n == "pass") { if (v.length() > 63) return "password must be at most 63 characters"; }
  else if (n == "server") {
    if (v.length() < 8 || v.length() > 120 || v.indexOf(' ') >= 0 || !(v.startsWith("http://") || v.startsWith("https://")))
      return "server must look like http://192.168.1.10:5000";
  } else if (n == "device") {
    if (v.length() < 1 || v.length() > 64) return "device id must be 1-64 characters";
    for (size_t i = 0; i < v.length(); i++) { char c = v[i]; if (!(isalnum((unsigned char)c) || c == '_' || c == '.' || c == '-')) return "device id: letters, digits, . _ - only"; }
  } else return "unknown setting";
  String val = v;
  if (n == "server") while (val.endsWith("/")) val.remove(val.length() - 1);
  if (!prefs.begin("pufcfg", false)) return "flash error";
  bool ok = val.length() == 0 ? (prefs.remove(n.c_str()), true) : prefs.putString(n.c_str(), val) > 0;
  prefs.end();
  return ok ? nullptr : "flash write failed";
}

/* ======================= printing ======================= */
static const char* resetReason() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON: return "POWERON";  case ESP_RST_BROWNOUT: return "BROWNOUT"; case ESP_RST_EXT: return "EXT";
    case ESP_RST_SW: return "SW";            case ESP_RST_PANIC: return "PANIC";       case ESP_RST_INT_WDT: return "INT_WDT";
    case ESP_RST_TASK_WDT: return "TASK_WDT"; case ESP_RST_WDT: return "WDT";          case ESP_RST_DEEPSLEEP: return "DEEPSLEEP";
    default: return "UNKNOWN";
  }
}
static void printResponse() {                            // capture mode only
  Serial.println(F("\n--- ESP32 256-bit SRAM PUF Response ---"));
  Serial.print(F("Reset Reason:     ")); Serial.println(resetReason());
  Serial.print(F("Binary (256-bit): "));
  for (uint8_t i = 0; i < PUF_BYTE_COUNT; i++) for (int8_t bit = 7; bit >= 0; bit--) Serial.print((puf_bytes[i] >> bit) & 1);
  Serial.println();
  Serial.print(F("Hex (256-bit):    0x"));
  for (uint8_t i = 0; i < PUF_BYTE_COUNT; i++) { if (puf_bytes[i] < 0x10) Serial.print('0'); Serial.print(puf_bytes[i], HEX); }
  Serial.println();
  uint16_t hw = 0;
  for (uint8_t i = 0; i < PUF_BYTE_COUNT; i++) hw += __builtin_popcount(puf_bytes[i]);
  Serial.print(F("Hamming Weight:   ")); Serial.print(hw); Serial.println(F(" / 256 bits"));
}
static void printStatus() {
  Helper h;
  Serial.print(F("PUF buffer @ 0x")); Serial.println((uint32_t)puf_bytes, HEX);
  if (loadHelper(h)) { Serial.print(F("Helper data in ESP: stored (t=")); Serial.print(h.t); Serial.print(F(", check=")); Serial.print(h.check.substring(0, 8)); Serial.println(F("...)")); }
  else Serial.println(F("Helper data in ESP: none"));
  Serial.print(F("Mode: ")); Serial.println(runMode ? F("run") : F("capture"));
}
static void printCfg() {                                  // never prints the password
  Config c = loadCfg(); Helper h;
  Serial.print(F("CFG_DATA mode=")); Serial.print(c.mode);
  Serial.print(F(" pass=")); Serial.print(c.pass.length() ? "set" : "empty");
  Serial.print(F(" helper=")); Serial.print(loadHelper(h) ? "stored" : "none");
  Serial.print(F(" registered=")); Serial.print(c.registered ? "yes" : "no");
  Serial.print(F(" device=")); Serial.print(c.device.length() ? c.device : String("-"));
  Serial.print(F(" server=")); Serial.print(c.server.length() ? c.server : String("-"));
  Serial.print(F(" ssid=")); Serial.println(c.ssid);
}

/* ======================= key rebuild (fuzzy extractor + HKDF-SHA-256) ======================= */
static bool isBits(const String& s, size_t n) { if (s.length() != n) return false; for (size_t i = 0; i < n; i++) if (s[i] != '0' && s[i] != '1') return false; return true; }
static bool isHex(const String& s, size_t mn, size_t mx, bool even) {
  if (s.length() < mn || s.length() > mx || (even && (s.length() & 1))) return false;
  for (size_t i = 0; i < s.length(); i++) if (!isxdigit((unsigned char)s[i])) return false;
  return true;
}
static void hmac256(const uint8_t* key, size_t kl, const uint8_t* msg, size_t ml, uint8_t* out) {
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, kl, msg, ml, out);
}
static bool deriveKey() {
  Helper h;
  if (!loadHelper(h)) { Serial.println(F("PUF: no helper data stored in this ESP32. Enrol and store it first.")); return false; }
  gfInit();
  uint8_t r[256], P[256], cw[256], fx[256], ikm[32];
  for (int i = 0; i < 256; i++) { P[i] = h.bits[i] - '0'; r[i] = ((pufCopy[i >> 3] >> (7 - (i & 7))) & 1) ^ P[i]; }
  int e = extDecode(r, h.t, cw);
  if (e < 0) { Serial.println(F("PUF: too many bit errors. Cut the power fully and restore it; if it repeats, enrol again with more sequences.")); return false; }
  for (int i = 0; i < 256; i++) fx[i] = cw[i] ^ P[i];
  memset(ikm, 0, sizeof ikm);
  for (int i = 0; i < 256; i++) if (fx[i]) ikm[i >> 3] |= 1 << (7 - (i & 7));
  uint8_t salt[32]; size_t sl = h.salt.length() / 2;
  for (size_t i = 0; i < sl; i++) { char t2[3] = {h.salt[2 * i], h.salt[2 * i + 1], 0}; salt[i] = (uint8_t)strtoul(t2, nullptr, 16); }
  uint8_t prk[32], msg[130];
  hmac256(salt, sl, ikm, 32, prk);                                   // HKDF-Extract
  size_t il = h.info.length();
  memcpy(msg, h.info.c_str(), il); msg[il] = 1;
  hmac256(prk, 32, msg, il + 1, KEY);                                // HKDF-Expand, T(1)
  uint8_t chk[43], dig[32];
  memcpy(chk, "PUFFE-check", 11); memcpy(chk + 11, KEY, 32);
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), chk, 43, dig);
  char hex[65]; for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", dig[i]);
  memset(ikm, 0, sizeof ikm); memset(fx, 0, sizeof fx); memset(prk, 0, sizeof prk);
  if (!h.check.equalsIgnoreCase(String(hex))) { memset(KEY, 0, sizeof KEY); Serial.println(F("PUF: key check FAILED (the stored helper data does not belong to this chip)")); return false; }
  pufErrors = e;
  Serial.printf("PUF: key reproduced, %d bit error(s) corrected\n", e);
  return true;
}

/* ======================= serial commands ======================= */
static String nextToken(String& s) { s.trim(); int p = s.indexOf(' '); String t = p < 0 ? s : s.substring(0, p); s = p < 0 ? String("") : s.substring(p + 1); return t; }

static void handleLine(String line) {
  line.trim();
  if (!line.length()) return;
  if (line == "HELPER?") {
    Helper h; if (!loadHelper(h)) { Serial.println(F("HELPER_NONE")); return; }
    Serial.print(F("HELPER_DATA ")); Serial.print(h.t); Serial.print(' '); Serial.print(h.bits); Serial.print(' '); Serial.print(h.salt);
    Serial.print(' '); Serial.print(h.check); Serial.print(' '); Serial.println(h.info); return;
  }
  if (line == "HELPER_CLEAR") { clearHelper(); Serial.println(F("HELPER_OK cleared")); return; }
  if (line.startsWith("HELPER ")) {
    String rest = line.substring(7); Helper h;
    h.t = nextToken(rest).toInt(); h.bits = nextToken(rest); h.salt = nextToken(rest); h.check = nextToken(rest); h.info = rest; h.info.trim();
    if (h.t < 1 || h.t > 32)                  { Serial.println(F("HELPER_ERR bad t")); return; }
    if (!isBits(h.bits, 256))                 { Serial.println(F("HELPER_ERR helper_bits must be 256 x 0/1")); return; }
    if (!isHex(h.salt, 2, 64, true))          { Serial.println(F("HELPER_ERR bad salt")); return; }
    if (!isHex(h.check, 64, 64, false))       { Serial.println(F("HELPER_ERR bad key_check")); return; }
    if (h.info.length() < 1 || h.info.length() > 120) { Serial.println(F("HELPER_ERR bad info")); return; }
    const char* r = saveHelper(h);
    if (!r) Serial.println(F("HELPER_ERR flash write failed"));
    else {
      Serial.print(F("HELPER_OK ")); Serial.println(r);
      if (strcmp(r, "unchanged") != 0) {                          // new helper data = new key: the old cloud registration no longer matches
        setReg(false); token = ""; WiFi.disconnect(true); WiFi.mode(WIFI_OFF);
        Serial.println(F("CFG_INFO registration cleared: register this device in the cloud again"));
      }
    }
    return;
  }
  if (line == "CFG?") { printCfg(); return; }
  if (line == "CFG_CLEAR") { if (prefs.begin("pufcfg", false)) { prefs.clear(); prefs.end(); } Serial.println(F("CFG_OK cleared")); return; }
  if (line.startsWith("CFG")) {
    String rest = line.substring(3); String name = nextToken(rest);
    const char* e = setCfg(name, rest);
    if (e) { Serial.print(F("CFG_ERR ")); Serial.println(e); }
    else {
      Serial.print(F("CFG_OK ")); Serial.println(name);
      if (name == "registered") {                                 // takes effect immediately
        cfg.registered = (rest == "1");
        if (!cfg.registered) { token = ""; WiFi.disconnect(true); WiFi.mode(WIFI_OFF); }
      }
    }
  }
}
static String rx; static bool rxOver = false;
static void pollSerial() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') { if (rxOver) Serial.println(F("CFG_ERR line too long")); else handleLine(rx); rx = ""; rxOver = false; }
    else if (c != '\r') { if (rx.length() < MAX_LINE) rx += c; else rxOver = true; }
  }
}

/* ======================= cloud (same protocol as server.py) ======================= */
static String hmacHex(const String& msg) {
  uint8_t mac[32]; char hex[65];
  hmac256(KEY, 32, (const uint8_t*)msg.c_str(), msg.length(), mac);
  for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", mac[i]);
  return String(hex);
}
static String field(const String& s, const char* k) {
  int i = s.indexOf(String("\"") + k + "\""); if (i < 0) return "";
  int c = s.indexOf(':', i), a = s.indexOf('"', c) + 1, b = s.indexOf('"', a);
  return (c > 0 && a > 0 && b > a) ? s.substring(a, b) : "";
}
static int httpGet(const String& url, String& body, const String& bearer = "") {
  HTTPClient http; http.begin(url); http.setConnectTimeout(4000); http.setTimeout(8000);
  if (bearer.length()) http.addHeader("Authorization", "Bearer " + bearer);
  int code = http.GET(); body = code > 0 ? http.getString() : http.errorToString(code); http.end(); return code;
}
static int httpPost(const String& url, const String& json, String& body, const String& bearer = "") {
  HTTPClient http; http.begin(url); http.setConnectTimeout(4000); http.setTimeout(8000); http.addHeader("Content-Type", "application/json");
  if (bearer.length()) http.addHeader("Authorization", "Bearer " + bearer);
  int code = http.POST(json); body = code > 0 ? http.getString() : http.errorToString(code); http.end(); return code;
}
static bool authenticate(bool showData) {
  if (!keyOK) { Serial.println(F("AUTH: cannot sign, the PUF key was not rebuilt (see the PUF: line at boot)")); return false; }
  String body; uint32_t t0 = millis();
  int c = httpGet(cfg.server + "/api/nonce?device_id=" + cfg.device, body);                // 1) GET nonce
  if (c != 200) { Serial.printf("AUTH: nonce failed: %d %s\n", c, body.c_str()); return false; }
  String nonce = field(body, "nonce");
  if (nonce.length() != 32) { Serial.println("AUTH: bad nonce reply: " + body); return false; }
  String resp = hmacHex(cfg.device + ":" + nonce);                                          // 2) sign it with the PUF key
  if (millis() - t0 > NONCE_BUDGET_MS) { Serial.println(F("AUTH: nonce too old, giving up")); return false; }
  String json = String("{\"device_id\":\"") + cfg.device + "\",\"nonce\":\"" + nonce + "\",\"response\":\"" + resp + "\"}";
  c = httpPost(cfg.server + "/api/auth", json, body);                                       // 3) POST proof
  if (c != 200) { Serial.printf("AUTH REJECTED: %d %s\n", c, body.c_str()); return false; }
  String tk = field(body, "token");
  if (!tk.length()) { Serial.println(F("AUTH: no token in the reply")); return false; }
  token = tk; tokenAt = millis();                                                           // session for telemetry
  Serial.println(F("AUTH OK"));
  if (!showData) return true;
  c = httpGet(cfg.server + "/api/data", body, token);                                       // 4) protected data
  Serial.printf("/api/data -> %d %s\n", c, body.c_str());
  return c == 200;
}

static bool tokenValid() { return token.length() && (millis() - tokenAt) < TOKEN_RENEW_MS; }
static int lastTeleCode = 0;
static float fakeTemp = 25.0f;
static void sendTelemetry() {                    // simulated sensor: a random temperature (replace with a real reading later)
  fakeTemp += random(-5, 6) / 10.0f;             // random walk, up to 0.5 degC per reading
  if (fakeTemp < 18.0f) fakeTemp = 18.0f;
  if (fakeTemp > 38.0f) fakeTemp = 38.0f;
  String j = String("{\"temperature_c\":") + String(fakeTemp, 1) + "}";
  String body; int c = httpPost(cfg.server + "/api/telemetry", j, body, token);
  if (c == 401 || c == 403) { token = ""; if (c != lastTeleCode) Serial.println(F("Telemetry: session rejected, authenticating again")); }
  else if (c != 200 && c != lastTeleCode) Serial.printf("Telemetry: failed (%d)\n", c);
  else if (c == 200 && lastTeleCode != 200) Serial.println(F("Telemetry: sending"));
  lastTeleCode = c;
}
static void connectWifi() {
  if (WiFi.status() == WL_CONNECTED) return;
  if (!cfg.ssid.length()) { Serial.println(F("WiFi: no ssid stored (dashboard, Wi-Fi & cloud tab)")); return; }
  Serial.print("WiFi: connecting to " + cfg.ssid);
  WiFi.mode(WIFI_STA); WiFi.begin(cfg.ssid.c_str(), cfg.pass.c_str());
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) { pollSerial(); delay(250); Serial.print('.'); }
  if (WiFi.status() == WL_CONNECTED) Serial.println(" connected, ESP32 IP " + WiFi.localIP().toString());
  else Serial.println(F(" failed, will retry (2.4 GHz only; check name and password)"));
}

/* ======================= main ======================= */
static uint32_t lastPrint = 0, lastPoll = 0, lastBeat = 0, lastWifiTry = 0, lastTele = 0, lastAuthTry = 0;
static bool triedAuth = false;
static int lastCode = 0;

void setup() {
  memcpy(pufCopy, puf_bytes, PUF_BYTE_COUNT);   // first thing: nothing below may touch the start-up state
  Serial.setRxBufferSize(1024);
  Serial.begin(115200);
  cfg = loadCfg();
  runMode = (cfg.mode == "run");
  if (!runMode) { printResponse(); printStatus(); lastPrint = millis(); return; }
  printStatus();
  keyOK = deriveKey();
  memset(pufCopy, 0, sizeof pufCopy);
  if (!cfg.server.length() || !cfg.device.length()) Serial.println(F("Run mode needs a server and a device id (dashboard, Wi-Fi & cloud tab)."));
  if (cfg.registered && keyOK) connectWifi();                    // Wi-Fi only for a registered device with a working key
  else {
    WiFi.mode(WIFI_OFF);
    if (!cfg.registered) Serial.println(F("Not registered in the cloud yet: Wi-Fi stays OFF. Use \"Register in cloud & go online\" in the dashboard."));
    else Serial.println(F("PUF key not available: Wi-Fi stays OFF."));
  }
}

void loop() {
  pollSerial();
  uint32_t now = millis();
  if (!runMode) {                                // capture mode: re-print so the host can catch it
    if (now - lastPrint >= 2000) { lastPrint = now; printResponse(); }
    delay(2); return;
  }
  if (now - lastBeat >= 2000) {                  // heartbeat: lets the DevKit see the board is alive
    lastBeat = now;
    Serial.printf("[run] wifi=%s reg=%s key=%s poll=%d token=%s\n", WiFi.status() == WL_CONNECTED ? "ok" : "off", cfg.registered ? "yes" : "no", keyOK ? "ok" : "no", lastCode, tokenValid() ? "ok" : "no");
  }
  if (!(cfg.registered && keyOK)) { delay(2); return; }          // not registered (or no key): no Wi-Fi, no cloud
  if (WiFi.status() != WL_CONNECTED) { if (now - lastWifiTry > 5000) { lastWifiTry = now; connectWifi(); } delay(2); return; }
  if (!cfg.server.length() || !cfg.device.length()) { delay(2); return; }
  if (now - lastPoll >= POLL_MS) {
    lastPoll = now;
    String body; int c = httpGet(cfg.server + "/api/poll?device_id=" + cfg.device, body);
    if (c != lastCode) {
      lastCode = c;
      if (c == 404) {                                            // the cloud has no such device (deleted, or wrong id): go offline
        Serial.println(F("Cloud: this device is not registered (unknown device id). Wi-Fi OFF until it is registered again."));
        setReg(false); token = ""; WiFi.disconnect(true); WiFi.mode(WIFI_OFF); return;
      }
      else if (c != 200) Serial.printf("Cloud: server not reachable (%d): check the server address and the laptop firewall (port 5000)\n", c);
      else Serial.println(F("Cloud: connected, polling"));
    }
    if (c == 200 && field(body, "command") == "authenticate") { Serial.println(F("Cloud asked this ESP32 to authenticate")); authenticate(true); }
  }
  // Self-authenticate (nonce challenge) whenever there is no valid session, then send telemetry with the token.
  if (keyOK && lastCode == 200 && !tokenValid() && (!triedAuth || now - lastAuthTry >= AUTH_RETRY_MS)) {
    triedAuth = true; lastAuthTry = now; authenticate(false);
  }
  if (tokenValid() && now - lastTele >= TELEMETRY_MS) { lastTele = now; sendTelemetry(); }
  delay(2);
}
