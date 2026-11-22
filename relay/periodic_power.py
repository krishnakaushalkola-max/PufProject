#!/usr/bin/env python3
"""Cold-reboot the WROOM through the USB HID relay (16c0:05df).

  python periodic_power.py                      # auto: ON 10 s / OFF 5 s forever
  python periodic_power.py --on 8 --off 12 --cycles 30
  python periodic_power.py --mode manual --off 8   # press Enter to cold-reboot

While running, type in the terminal (changes apply from the next phase):
  on <s> | off <s> | auto | manual | reboot (or just Enter) | status | quit
Close the dashboard's relay connection first: only one program can hold the relay.
"""
import argparse, sys, threading, time
import hid

VID, PID = 0x16C0, 0x05DF


class Relay:
    def __init__(self, channel, invert):
        self.ch, self.invert = channel, invert
        self.dev = hid.device()
        self.dev.open(VID, PID)

    def power(self, on):
        eff = (not on) if self.invert else on
        self.dev.send_feature_report([0x00, 0xFF if eff else 0xFD, self.ch, 0, 0, 0, 0, 0, 0])

    def close(self):
        self.dev.close()


class Cfg:
    def __init__(self, a):
        self.on, self.off, self.auto, self.cycles = a.on, a.off, a.mode == "auto", a.cycles
        self.kick, self.quit = threading.Event(), threading.Event()


def nap(cfg, secs, interruptible):
    end = time.monotonic() + secs
    while not cfg.quit.is_set():
        left = end - time.monotonic()
        if left <= 0:
            return
        if interruptible and cfg.kick.is_set():
            return
        time.sleep(min(0.1, left))


def commands(cfg):
    for raw in sys.stdin:
        p = raw.split()
        if not p or p[0] == "reboot":
            cfg.kick.set()
        elif p[0] in ("on", "off") and len(p) == 2:
            try:
                setattr(cfg, p[0], max(0.1, float(p[1])))
                print(f"{p[0]} time = {getattr(cfg, p[0]):g} s")
            except ValueError:
                print("usage: on <seconds> | off <seconds>")
        elif p[0] in ("auto", "manual"):
            cfg.auto = p[0] == "auto"
            print("mode:", p[0])
        elif p[0] == "status":
            print(f"mode={'auto' if cfg.auto else 'manual'} on={cfg.on:g}s off={cfg.off:g}s cycles={cfg.cycles or 'forever'}")
        elif p[0] in ("quit", "q"):
            cfg.quit.set()
        else:
            print("commands: on <s> | off <s> | auto | manual | reboot/Enter | status | quit")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["auto", "manual"], default="auto")
    ap.add_argument("--on", type=float, default=10.0, help="seconds the WROOM stays powered (auto)")
    ap.add_argument("--off", type=float, default=5.0, help="seconds fully unpowered")
    ap.add_argument("--cycles", type=int, default=0, help="0 = run until Ctrl+C")
    ap.add_argument("--channel", type=int, default=2)
    ap.add_argument("--invert", action="store_true", help="WROOM wired to the NC contact")
    a = ap.parse_args()

    cfg, relay = Cfg(a), Relay(a.channel, a.invert)
    threading.Thread(target=commands, args=(cfg,), daemon=True).start()
    n = 0
    try:
        if not cfg.auto:
            relay.power(True)
            print("Manual mode: WROOM ON. Press Enter to cold-reboot (type 'auto' for auto mode).")
        while not cfg.quit.is_set():
            if cfg.auto:
                if cfg.cycles and n >= cfg.cycles:
                    break
                n += 1
                print(f"Cycle {n}: WROOM ON ({cfg.on:g} s, Enter = cut now)")
                relay.power(True)
                nap(cfg, cfg.on, True)
                cfg.kick.clear()
                print(f"Cycle {n}: WROOM OFF ({cfg.off:g} s)")
                relay.power(False)
                nap(cfg, cfg.off, False)
            elif cfg.kick.wait(0.2):
                cfg.kick.clear()
                print(f"Cold reboot: OFF {cfg.off:g} s")
                relay.power(False)
                nap(cfg, cfg.off, False)
                relay.power(True)
                print("WROOM ON")
    except KeyboardInterrupt:
        print("Stopped")
    finally:
        relay.power(False)   # always leave the WROOM off
        relay.close()


if __name__ == "__main__":
    main()
