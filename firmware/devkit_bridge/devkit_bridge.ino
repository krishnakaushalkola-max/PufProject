// DevKit V1 bridge: WROOM TX -> DevKit GPIO16 (RX2), common GND.
// Do NOT wire GPIO17 (TX2) to the WROOM: it would back-feed the WROOM while its relay is off.
// Every WROOM line is forwarded to the laptop as "[12.3s] <line>".
// The dashboard also reads the two markers "--- WROOM is ON ---" / "--- WROOM is OFF (no data) ---".
#define SILENCE_MS 3000   // no data for this long = WROOM is off (WROOM prints every 2 s)

String line = "";
unsigned long lastRx = 0;
bool silent = true;

void setup() {
  Serial.begin(115200);                       // to laptop / dashboard
  Serial2.begin(115200, SERIAL_8N1, 16, 17);  // RX2 = GPIO16, TX2 = GPIO17 (leave TX2 unconnected)
  Serial.println("DevKit ready, waiting for WROOM...");
}

void loop() {
  while (Serial2.available()) {
    char c = Serial2.read();
    lastRx = millis();
    if (silent) {
      Serial.println("--- WROOM is ON ---");
      silent = false;
    }
    if (c == '\n') {
      Serial.println("[" + String(millis() / 1000.0, 1) + "s] " + line);
      line = "";
    } else if (c != '\r') {
      if (line.length() < 600) line += c;
    }
  }

  if (!silent && millis() - lastRx > SILENCE_MS) {
    Serial.println("--- WROOM is OFF (no data) ---");
    silent = true;
    line = "";
  }
}
