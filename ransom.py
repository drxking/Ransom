#!/usr/bin/env python3
"""
file_locker_demo.py
Educational, non-malicious demo that encrypts/decrypts COPIES of .docx files
inside a folder you explicitly mark with a consent file.

Safety rails:
  - Operates ONLY within a user-chosen directory that contains a file named
    'I_CONSENT_TO_ENCRYPT_THIS_FOLDER'
  - Never deletes or modifies originals; writes encrypted copies to ./locked/
    and decrypted copies to ./restored/
  - Requires explicit --mode encrypt|decrypt

Usage:
  python3 file_locker_demo.py --dir /path/to/lab_docs --mode encrypt
  python3 file_locker_demo.py --dir /path/to/lab_docs --mode decrypt

Prereqs:
  pip install cryptography
"""

import argparse
import os
from pathlib import Path
from typing import List
from hashlib import sha256

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception as e:
    raise SystemExit(
        "Missing dependency. Install with:  pip install cryptography\n"
        f"Underlying error: {e}"
    )

# --------------------------------------------------------------------
# EMBEDDED KEY (for demo reproducibility ONLY — never embed keys in real apps)
# You may also override via environment variable FILE_LOCKER_KEY.
# --------------------------------------------------------------------
EMBEDDED_KEY = b'RjJj9q2S8fQb7oqw5Qv0XG2k6s2Kc8aTzF8kC1sJZoE='  # example Fernet key
KEY = os.environ.get("FILE_LOCKER_KEY", EMBEDDED_KEY).strip() if isinstance(EMBEDDED_KEY, bytes) else os.environ.get("FILE_LOCKER_KEY", EMBEDDED_KEY).encode()

CONSENT_FILENAME = "I_CONSENT_TO_ENCRYPT_THIS_FOLDER"
LOCKED_DIRNAME = "locked"
RESTORED_DIRNAME = "restored"

def find_docx(root: Path) -> List[Path]:
    return sorted([p for p in root.glob("*.docx") if p.is_file()])

def sha256_hex(p: Path) -> str:
    h = sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def encrypt_copies(root: Path, key: bytes) -> None:
    fern = Fernet(key)
    outdir = root / LOCKED_DIRNAME
    outdir.mkdir(exist_ok=True)
    files = find_docx(root)
    if not files:
        print("[=] No .docx files found to encrypt.")
        return
    print(f"[+] Encrypting COPIES of {len(files)} files into {outdir} ...")
    for src in files:
        data = src.read_bytes()
        ct = fern.encrypt(data)
        dst = outdir / (src.name + ".enc")
        dst.write_bytes(ct)
        print(f"  • {src.name}  ->  {dst.name}  | orig_sha256={sha256_hex(src)}")
    print("[✓] Done. Originals are untouched.")

def decrypt_copies(root: Path, key: bytes) -> None:
    fern = Fernet(key)
    encdir = root / LOCKED_DIRNAME
    if not encdir.exists():
        print(f"[!] Encrypted dir not found: {encdir}")
        return
    outdir = root / RESTORED_DIRNAME
    outdir.mkdir(exist_ok=True)

    enc_files = sorted([p for p in encdir.glob("*.docx.enc") if p.is_file()])
    # Backward-compatible: also accept "*.enc"
    if not enc_files:
        enc_files = sorted([p for p in encdir.glob("*.enc") if p.is_file()])

    if not enc_files:
        print("[=] No encrypted files found to restore.")
        return

    print(f"[+] Decrypting {len(enc_files)} files into {outdir} ...")
    for enc in enc_files:
        try:
            pt = fern.decrypt(enc.read_bytes())
        except InvalidToken:
            print(f"  ✗ Invalid key for {enc.name}")
            continue
        # Remove .enc suffix
        base_name = enc.name[:-4] if enc.name.endswith(".enc") else enc.stem
        # If the base still has ".docx", keep it; otherwise ensure it ends with .docx
        dst_name = base_name if base_name.endswith(".docx") else base_name + ".docx"
        dst = outdir / dst_name
        dst.write_bytes(pt)
        print(f"  • {enc.name}  ->  {dst.name}  | restored_sha256={sha256_hex(dst)}")
    print("[✓] Done. Restored copies written. Compare hashes with originals to verify.")

def require_consent_folder(target: Path) -> None:
    consent = target / CONSENT_FILENAME
    if not consent.exists():
        raise SystemExit(
            f"\nSAFETY STOP:\n"
            f"  The directory '{target}' is NOT marked for this demo.\n"
            f"  Create an empty file named '{CONSENT_FILENAME}' inside it to proceed.\n"
            f"  Example:\n"
            f"    mkdir -p {target}\n"
            f"    touch {consent}\n"
            f"  Then re-run this script.\n"
        )

def main():
    ap = argparse.ArgumentParser(
        description="Safe file-locker demo (educational). Encrypts/decrypts COPIES of .docx files."
    )
    ap.add_argument("--dir", required=True, help="Target folder that YOU created for the lab.")
    ap.add_argument("--mode", choices=["encrypt", "decrypt"], required=True, help="Operation mode.")
    args = ap.parse_args()

    target = Path(args.dir).expanduser().resolve()
    if not target.exists() or not target.is_dir():
        raise SystemExit(f"[!] Not a directory: {target}")

    # Safety consent gate
    require_consent_folder(target)

    print(f"[i] Demo key in use (base64): {KEY.decode() if isinstance(KEY, (bytes, bytearray)) else KEY}")
    print(f"[i] Target directory: {target}")

    if args.mode == "encrypt":
        encrypt_copies(target, KEY if isinstance(KEY, (bytes, bytearray)) else KEY.encode())
    else:
        decrypt_copies(target, KEY if isinstance(KEY, (bytes, bytearray)) else KEY.encode())

if __name__ == "__main__":
    main()
