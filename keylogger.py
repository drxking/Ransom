#!/usr/bin/env python3
"""
keystroke_sim.py — Benign, consent-based keystroke *simulation*.
Records only keys typed into this terminal while it has focus.

Safety rails:
  - Works only inside a chosen lab folder containing:
        I_CONSENT_TO_KEYLOG_DEMO
  - No background monitoring. No /dev/input access. No system hooks.
  - Exit with ESC or Ctrl-C.

Usage:
  mkdir -p ~/keylog_lab && touch ~/keylog_lab/I_CONSENT_TO_KEYLOG_DEMO
  python3 keystroke_sim.py --dir ~/keylog_lab
"""

import argparse, sys, os, time
from pathlib import Path
import termios, tty

MARKER = "I_CONSENT_TO_KEYLOG_DEMO"
LOGFILE = "keystrokes.log"

def ensure_consent(lab: Path):
    if not lab.is_dir():
        sys.exit(f"[!] Not a directory: {lab}")
    if not (lab / MARKER).exists():
        sys.exit(
            f"\nSAFETY STOP:\n"
            f"  '{lab}' is not marked for this demo.\n"
            f"  Create the marker file first:\n"
            f"    touch {lab / MARKER}\n"
        )

def main():
    ap = argparse.ArgumentParser(description="Benign keystroke simulation (foreground only).")
    ap.add_argument("--dir", required=True, help="Lab directory with consent marker.")
    args = ap.parse_args()

    lab = Path(args.dir).expanduser().resolve()
    ensure_consent(lab)
    log_path = lab / LOGFILE

    print(f"[i] Writing to: {log_path}")
    print("[i] Type some keys. Press ESC to exit.\n")

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)  # read key-by-key
        with log_path.open("a", encoding="utf-8") as f:
            while True:
                ch = sys.stdin.read(1)
                ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
                if ch == "\x1b":  # ESC
                    print("\n[i] ESC received. Exiting.")
                    break
                # Represent control characters nicely
                rep = {
                    "\r": "\\r", "\n": "\\n", "\t": "\\t",
                    "\x7f": "BACKSPACE", "\x03": "CTRL-C"
                }.get(ch, ch)
                line = f"[{ts}Z] KEY: {rep}\n"
                f.write(line); f.flush()
                # echo a dot so user sees progress without revealing the key
                sys.stdout.write("·"); sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

if __name__ == "__main__":
    main()
