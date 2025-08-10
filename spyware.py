#!/usr/bin/env python3
"""
activity_logger_demo.py  —  Benign, consent-based telemetry demo for class.

Purpose:
  Simulate "spyware-like" logging safely by recording ONLY synthetic events
  that the user manually enters. No background monitoring. No real data access.

Safety:
  - Operates ONLY in a folder containing a marker file:
      I_CONSENT_TO_LOG_THIS_DEMO
  - Writes events to events.jsonl (JSON lines) and a human-readable events.log
  - Optional hashing/redaction to demonstrate privacy-by-design concepts.

Usage:
  mkdir -p ~/spyware_demo
  touch ~/spyware_demo/I_CONSENT_TO_LOG_THIS_DEMO
  python3 activity_logger_demo.py --dir ~/spyware_demo
  (then follow the on-screen menu)

Options:
  --hash-content    Store SHA-256 hashes of "content" fields instead of plaintext.
  --redact          Redact emails/phone numbers from content before storing.
"""

import argparse, json, os, re, sys
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Dict, Any, Optional, List

CONSENT_FILE = "I_CONSENT_TO_LOG_THIS_DEMO"
EVENTS_JSONL = "events.jsonl"
EVENTS_TXT = "events.log"

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\-\s]{6,}\d")

def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def redact(text: str) -> str:
    text = EMAIL_RE.sub("[EMAIL_REDACTED]", text)
    text = PHONE_RE.sub("[PHONE_REDACTED]", text)
    return text

def maybe_hash(text: str, do_hash: bool) -> str:
    return sha256(text.encode()).hexdigest() if do_hash else text

def write_event(dirpath: Path, event: Dict[str, Any]) -> None:
    jsonl = dirpath / EVENTS_JSONL
    txt   = dirpath / EVENTS_TXT
    with jsonl.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    # human-readable line
    with txt.open("a", encoding="utf-8") as f:
        f.write(f"[{event['timestamp']}] {event['type']}: {event.get('summary','')}\n")

def load_last_events(dirpath: Path, n: int = 10) -> List[Dict[str, Any]]:
    jsonl = dirpath / EVENTS_JSONL
    if not jsonl.exists():
        return []
    # read last n lines efficiently
    lines = jsonl.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines[-n:]:
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out

def prompt(msg: str) -> str:
    try:
        return input(msg).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

def ensure_consent(dirpath: Path) -> None:
    if not (dirpath / CONSENT_FILE).exists():
        sys.exit(
            f"\nSAFETY STOP:\n"
            f"  '{dirpath}' is not marked for this demo.\n"
            f"  Create the marker file first:\n"
            f"    touch {dirpath / CONSENT_FILE}\n"
        )

def main():
    ap = argparse.ArgumentParser(description="Benign activity logger demo (educational).")
    ap.add_argument("--dir", required=True, help="Target folder (must contain consent marker).")
    ap.add_argument("--hash-content", action="store_true", help="Hash content fields with SHA-256.")
    ap.add_argument("--redact", action="store_true", help="Redact emails/phones in content.")
    args = ap.parse_args()

    dirpath = Path(args.dir).expanduser().resolve()
    if not dirpath.exists() or not dirpath.is_dir():
        sys.exit(f"[!] Not a directory: {dirpath}")

    ensure_consent(dirpath)
    print(f"[i] Logging to: {dirpath / EVENTS_JSONL}")
    print(f"[i] Human-readable log: {dirpath / EVENTS_TXT}")
    print(f"[i] Privacy modes — hash: {args.hash_content}, redact: {args.redact}")
    print("\n--- MENU ---")
    print("1) Log synthetic browser visit (you type the URL/title)")
    print("2) Log synthetic clipboard content (you paste text here)")
    print("3) Log custom event (name + details)")
    print("4) Show last 10 events")
    print("5) Rotate logs (archive current files)")
    print("0) Exit")

    while True:
        choice = prompt("\nSelect an option (0-5): ")
        ts = now_iso()

        if choice == "1":
            url = prompt("Enter a fake URL you 'visited' (e.g., https://example.com): ")
            title = prompt("Enter a fake page title: ")
            content = f"{title} | {url}"
            if args.redact:
                content = redact(content)
            stored = maybe_hash(content, args.hash_content)
            ev = {
                "timestamp": ts,
                "type": "browser_visit_demo",
                "url": url,
                "title": title,
                "content_stored": "hash" if args.hash_content else "plaintext",
                "summary": f"Visited {url} ({title})",
                "data": stored,
            }
            write_event(dirpath, ev)
            print("[✓] Logged synthetic browser visit.")

        elif choice == "2":
            clip = prompt("Paste some FAKE 'clipboard' text to log (you control this): ")
            original = clip
            if args.redact:
                clip = redact(clip)
            stored = maybe_hash(clip, args.hash_content)
            ev = {
                "timestamp": ts,
                "type": "clipboard_demo",
                "summary": "Clipboard content logged (synthetic, user-provided)",
                "content_stored": "hash" if args.hash_content else "plaintext",
                "length": len(original),
                "data": stored,
            }
            write_event(dirpath, ev)
            print("[✓] Logged synthetic clipboard text.")

        elif choice == "3":
            name = prompt("Custom event name (e.g., button_click): ")
            details = prompt("Details (short): ")
            if args.redact:
                details = redact(details)
            stored = maybe_hash(details, args.hash_content)
            ev = {
                "timestamp": ts,
                "type": f"custom:{name}",
                "summary": f"Custom event: {name}",
                "content_stored": "hash" if args.hash_content else "plaintext",
                "data": stored,
            }
            write_event(dirpath, ev)
            print("[✓] Logged custom event.")

        elif choice == "4":
            events = load_last_events(dirpath, n=10)
            if not events:
                print("[=] No events yet.")
            else:
                print("\nLast 10 events:")
                for e in events:
                    print(json.dumps(e, ensure_ascii=False))
        elif choice == "5":
            # simple rotation
            jsonl = dirpath / EVENTS_JSONL
            txt = dirpath / EVENTS_TXT
            if jsonl.exists():
                jsonl.rename(dirpath / f"{EVENTS_JSONL}.{datetime.utcnow().strftime('%Y%m%d%H%M%S')}")
            if txt.exists():
                txt.rename(dirpath / f"{EVENTS_TXT}.{datetime.utcnow().strftime('%Y%m%d%H%M%S')}")
            print("[✓] Rotated logs.")
        elif choice == "0":
            print("Bye.")
            break
        else:
            print("Pick 0-5.")

if __name__ == "__main__":
    main()
