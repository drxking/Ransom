#!/usr/bin/env python3
"""
trojan_demo_cli.py  —  Benign CLI demo of a Trojan-style "hidden action".

Advertised action (benign, visible):
  - Print file info (size, mime guess, SHA-256)

Hidden side effect (still benign, for demo only):
  - Append a note and a log entry inside the lab directory.

Safety rails:
  - Operates ONLY inside a user-specified lab folder that contains:
        I_CONSENT_TO_DEMO_TROJAN
  - Target file MUST be inside that lab folder.
  - No deletion, no persistence, no networking.

Usage:
  python3 trojan_demo_cli.py --dir ~/trojan_lab --target ~/trojan_lab/sample.png
"""

import argparse
import hashlib
import mimetypes
import os
from pathlib import Path
from datetime import datetime
import sys

MARKER = "I_CONSENT_TO_DEMO_TROJAN"
NOTE_FILE = "DEMO_SIDE_EFFECT.txt"
LOG_FILE  = "trojan_demo.log"

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

def is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except Exception:
        return False

def sha256_hex(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def visible_file_info(target: Path):
    size = target.stat().st_size
    mime, _ = mimetypes.guess_type(target.name)
    digest = sha256_hex(target)
    print("=== FILE INFO ===")
    print(f"Path    : {target}")
    print(f"Size    : {size} bytes")
    print(f"MIME    : {mime or 'unknown'}")
    print(f"SHA-256 : {digest}")

def benign_side_effect(lab: Path, target: Path):
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    note = lab / NOTE_FILE
    log  = lab / LOG_FILE
    # A visible, harmless note
    with note.open("a", encoding="utf-8") as f:
        f.write("This note was created by the benign Trojan CLI demo.\n")
    # A log entry describing what happened
    with log.open("a", encoding="utf-8") as f:
        f.write(f"[{ts}] Processed: {target.name}\n")

def main():
    ap = argparse.ArgumentParser(description="Benign Trojan concept demo (CLI).")
    ap.add_argument("--dir", required=True, help="Lab directory containing consent marker.")
    ap.add_argument("--target", required=True, help="Target file INSIDE the lab directory.")
    args = ap.parse_args()

    lab = Path(args.dir).expanduser().resolve()
    target = Path(args.target).expanduser().resolve()

    ensure_consent(lab)

    if not target.exists() or not target.is_file():
        sys.exit(f"[!] Target is not a file: {target}")
    if not is_within(target, lab):
        sys.exit("[!] Target must be INSIDE the lab directory.")

    # Advertised benign action
    visible_file_info(target)

    # Trojan-style side action (benign)
    benign_side_effect(lab, target)

    print("\n[info] Demo side effect wrote/updated:")
    print(f" - {lab / NOTE_FILE}")
    print(f" - {lab / LOG_FILE}")

if __name__ == "__main__":
    main()
