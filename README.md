# SRAM PUF project

- dashboard/puf_dashboard_256_2.html   open in Chrome/Edge. Connect the DevKit's USB serial port, then the relay (WebHID).
- firmware/devkit_bridge/devkit_bridge.ino   flash to the DevKit V1 (forwards WROOM UART to the laptop).
- firmware/puf_response_1/puf_response_1.ino   flash to the ESP32-WROOM (prints the 256-bit start-up SRAM).
- relay/periodic_power.py   standalone relay timer (pip install hidapi). Run it OR use the dashboard's relay buttons, not both.

Wiring: WROOM TX -> DevKit GPIO16, common GND. Leave DevKit GPIO17 unconnected. Relay channel 2 switches the WROOM's supply.

Dashboard timing: "off time" = power-cut length, "on time" = hold time per auto cycle, "cycles" 0 = until stopped.
"Cold reboot now" does one manual cycle; "Auto cold-reboot" repeats. Changes to times apply from the next cycle.
With periodic_power.py running instead, leave "also capture boots caused by anything else" ticked and the dashboard records every boot.
