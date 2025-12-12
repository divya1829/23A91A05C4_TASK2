#!/usr/bin/env python3
import time, os
from datetime import datetime, timezone
from pathlib import Path
from totp_utils import generate_totp_code

SEED_FILE = Path("/data/seed.txt")
OUT_FILE = Path("/cron/last_code.txt")

def main():
    try:
        if not SEED_FILE.exists():
            raise FileNotFoundError("seed not found")
        hex_seed = SEED_FILE.read_text().strip()
        code = generate_totp_code(hex_seed)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        line = f"{ts} - 2FA Code: {code}\n"
        # append
        OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(OUT_FILE, "a") as f:
            f.write(line)
    except Exception as e:
        # log error to stderr (cron will redirect)
        import sys
        print(str(e), file=sys.stderr)

if __name__ == "__main__":
    main()
