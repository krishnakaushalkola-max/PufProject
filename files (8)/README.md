# SRAM-PUF device authentication (one WROOM-32 + one DevKit V1 bridge)

puf_final/
  cloud/server.py, dashboard.html, device.html, puf_dashboard.html   (run on the laptop: python server.py)
  firmware/devkit_bridge/devkit_bridge.ino   -> flash ONCE to the DevKit V1
  firmware/puf_auth/puf_auth.ino             -> flash ONCE to the WROOM-32
Everything else (capture, enrol, helper data, Wi-Fi, registration, mode) is done from the dashboard. No more flashing.

## Connections (never change after this)
- WROOM TX0 -> DevKit RX2 (GPIO16);  DevKit TX2 (GPIO17) -> WROOM RX0 (pin "RX");  WROOM GND -> DevKit GND
- WROOM power ONLY from the relay output. DevKit GPIO4 stays unconnected.
- DevKit USB and relay USB to the laptop. WROOM USB unplugged (only for flashing).
- If your DevKit has no RX2/TX2 pins: use D25 (receive), D26 (send), D18 (unconnected) and change RX_PIN, TX_PIN, IDLE_TX_PIN at the top of devkit_bridge.ino.

## 1. Flash (once)
Close the dashboard. DevKit: upload devkit_bridge.ino. WROOM: relay OFF, WROOM USB in, upload puf_auth.ino
(BOOT button if "Connecting...", or pull only the wire on WROOM RX0 during the upload), then unplug the WROOM USB.

## 2. Start the cloud
cd cloud ; pip install flask ; python server.py   (note the admin token it prints)
Allow TCP 5000 in Windows Firewall. Find the laptop's Wi-Fi IP with ipconfig.
Open http://localhost:5000/puf  (use localhost, not the IP: the browser only allows serial/USB access there).

## 3. Enrol (page http://localhost:5000/puf, Chrome/Edge)
1. 1 Connect DevKit serial, 2 Connect relay, WROOM power ON. Log: "Mode: capture".
2. Cycles 20, Auto cold-reboot, wait for 20 sequences.
3. Fuzzy extractor tab: Enrollment readings 19, Enroll & generate key (success rate 100%).
4. Download helper data (store in ESP32 ticked): log "stored".

## 4. Register and go online (one click)
Wi-Fi & cloud tab: Wi-Fi name, Wi-Fi password, server http://<laptop IP>:5000, device ID (esp32-001), cloud admin token.
Click "Register in cloud & go online". The dashboard (1) registers the key in the cloud, (2) sends the settings with mode run,
(3) only then marks the WROOM as registered. The WROOM never joins Wi-Fi before step 3.
Then WROOM power OFF, wait 4 s, WROOM power ON. Log: PUF: key reproduced -> WiFi connected -> Cloud: connected, polling ->
AUTH OK -> Telemetry: sending.

## 5. Device page
http://localhost:5000 -> Devices tab -> Open page (or http://localhost:5000/device/esp32-001). Shows the nonce handshake and the
temperature telemetry (simulated random temperature for now; edit sendTelemetry() in puf_auth.ino for a real sensor).

## Rules the WROOM follows
- capture mode (default): prints the PUF response, no Wi-Fi.
- run mode: Wi-Fi only if registered=yes AND the PUF key was rebuilt. Otherwise Wi-Fi stays OFF.
- Storing new helper data clears "registered" (the old cloud key no longer matches): register again.
- If the cloud answers "unknown device" (deleted from the cloud), the WROOM clears "registered" and turns Wi-Fi off.

## Enrol again later
Wi-Fi & cloud tab: mode capture -> Send settings only, power-cycle, repeat steps 3 and 4 (the cloud asks to replace the old key).
