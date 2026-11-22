# SRAM PUF: helper data stored in the ESP32 WROOM

Files
- puf_response_2/puf_response_2.ino  Flash to the WROOM. Prints the 256-bit SRAM response and stores/returns helper data in its flash (NVS).
- puf_dashboard_256_3.html          Open in Chrome/Edge. DevKit capture, relay control, fuzzy extractor, ESP32 helper-data storage.

Store helper data in the WROOM
1. Flash puf_response_2.ino to the WROOM (Arduino IDE, WROOM USB).
2. With the relay + DevKit bridge, collect a few cold-boot sequences, then Fuzzy extractor -> Enroll.
3. Plug the WROOM's USB into the PC, click "3. Connect WROOM USB" and choose the WROOM's port (not the DevKit's).
4. Click "Download helper data" with "store in ESP32" ticked. The log shows stored / REPLACED / unchanged.
   A copy is also saved as helper_data.json (backup).
5. Power-cycle the WROOM. Its serial output should say "Helper data in ESP: stored (t=...)".
   "Load helper data from ESP32" reads it back.

Serial commands on the WROOM (115200 baud): HELPER <t> <256 bits> <salt> <key_check> <info>, HELPER?, HELPER_CLEAR.

Notes
- Disconnect the WROOM USB before cold-reboot captures; the cable can power the board.
- Enroll with puf_response_2.ino so enrollment and later key rebuilding read the same memory cells
  (the sketch prints "PUF buffer @ 0x..." at boot).
- The key is never stored; helper data is public by design.
- Not yet included: firmware that rebuilds the key and answers the cloud challenge (needs the cloud protocol).

## No-cable-change setup (DevKit bridge both ways)
One-time wiring, then never touched again:
- WROOM TX0 -> DevKit GPIO16, WROOM GND -> DevKit GND (as before)
- NEW: DevKit GPIO17 -> WROOM RX0 (labelled "RX")
- DevKit GPIO4 stays unconnected; the relay powers the WROOM; the WROOM USB stays unplugged.
Flash devkit_bridge/devkit_bridge.ino to the DevKit. Then everything works from the DevKit USB + relay USB:
capture cold boots, Download helper data (goes to the WROOM flash through the DevKit), Load helper data from ESP32,
and watch/type to the WROOM in the Arduino Serial Monitor on the DevKit's port (115200, Newline; try HELPER?).
Close the dashboard first, only one program can use a port.
