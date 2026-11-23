// ESP32 DevKit V1 bridge between the PC (USB) and the WROOM-32 under test.
//
//  WROOM -> PC : every line the WROOM prints (WROOM TX0 -> DevKit GPIO16) is relayed with a
//                "[12.3s] " prefix, plus "--- WROOM is ON ---" / "--- WROOM is OFF (no data) ---"
//                markers (format used by puf_dashboard_256_3.html).
//  PC -> WROOM : lines starting with HELPER or CFG (helper data and settings commands) are forwarded
//                to the WROOM (DevKit GPIO17 -> WROOM RX0), so helper data can be stored and read
//                with no cable changes. Works from the dashboard or the Arduino Serial Monitor.
//
// GPIO17 is only DRIVEN while a command is being sent. Otherwise it is high-impedance, so the
// DevKit can never back-power the WROOM through its RX pin when the relay is off.
// Wiring: WROOM TX0 -> GPIO16, DevKit GPIO17 -> WROOM RX0, common GND. Leave GPIO4 unconnected.

#include <Arduino.h>

#define PC_BAUD      115200
#define WROOM_BAUD   115200
#define RX_PIN       16        // from WROOM TX0
#define TX_PIN       17        // to WROOM RX0 (driven only while sending)
#define IDLE_TX_PIN  4         // UART2's TX is parked here while idle; keep this pin unconnected
#define SILENCE_MS   3000      // no data this long -> WROOM reported OFF
#define TX_HOLD_MS   1500      // keep GPIO17 driven this long after a send, to catch the reply
#define MAX_LINE     700       // a HELPER line is about 400 characters

static char   rxBuf[MAX_LINE + 1];
static size_t rxLen = 0;
static bool   wroomOn = false;
static uint32_t lastRx = 0;
static bool   txDriven = false;
static uint32_t lastTx = 0;
static String pcLine;
static bool   pcOver = false;

static void beginUart(int txPin) {
  Serial2.setRxBufferSize(1024);                 // allowed only while the UART is stopped
  Serial2.begin(WROOM_BAUD, SERIAL_8N1, RX_PIN, txPin);
}
static void uartIdle() {                         // receive only; GPIO17 high-impedance
  Serial2.end();
  pinMode(TX_PIN, INPUT);
  beginUart(IDLE_TX_PIN);
  txDriven = false;
}
static void uartDrive() {                        // GPIO17 becomes the UART TX
  Serial2.end();
  beginUart(TX_PIN);
  txDriven = true;
}

static void stamp() { Serial.printf("[%.1fs] ", millis() / 1000.0); }

static void emitLine() {
  if (rxLen > 0) { rxBuf[rxLen] = 0; stamp(); Serial.println(rxBuf); }
  rxLen = 0;
}

static void pollWroom() {
  while (Serial2.available()) {
    int c = Serial2.read();
    bool ok = (c == '\n' || c == '\r' || c == '\t' || (c >= 32 && c < 127));
    if (!ok) continue;                           // ignore noise while the WROOM is unpowered
    lastRx = millis();
    if (!wroomOn) { wroomOn = true; stamp(); Serial.println(F("--- WROOM is ON ---")); }
    if (c == '\n') emitLine();
    else if (c != '\r' && rxLen < MAX_LINE) rxBuf[rxLen++] = (char)c;
  }
  if (wroomOn && millis() - lastRx > SILENCE_MS) {
    wroomOn = false; rxLen = 0;
    stamp(); Serial.println(F("--- WROOM is OFF (no data) ---"));
  }
}

static void forwardToWroom(const String& l) {
  if (!wroomOn) {                                // nothing to talk to; stay high-impedance
    stamp(); Serial.println(F("HELPER_ERR WROOM is off (relay OFF), nothing sent"));
    return;
  }
  if (!txDriven) uartDrive();
  Serial2.print(l);
  Serial2.print('\n');
  Serial2.flush();
  lastTx = millis();
  stamp(); Serial.print(F("BRIDGE_FWD ")); Serial.print(l.length()); Serial.println(F(" bytes sent to WROOM"));
}

static void pollPc() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') {
      if (!pcOver) { pcLine.trim(); if (pcLine.startsWith("HELPER") || pcLine.startsWith("CFG")) forwardToWroom(pcLine); }
      else { stamp(); Serial.println(F("HELPER_ERR line too long")); }
      pcLine = ""; pcOver = false;
    } else if (c != '\r') {
      if (pcLine.length() < MAX_LINE) pcLine += c; else pcOver = true;
    }
  }
}

void setup() {
  Serial.setRxBufferSize(1024);
  Serial.begin(PC_BAUD);
  pinMode(TX_PIN, INPUT);                        // high-impedance from the start
  beginUart(IDLE_TX_PIN);
  lastRx = millis();
  stamp(); Serial.println(F("DevKit ready: WROOM TX0 -> GPIO16, HELPER commands -> GPIO17"));
}

void loop() {
  pollWroom();
  pollPc();
  if (txDriven && millis() - lastTx > TX_HOLD_MS) uartIdle();
  delay(1);
}
