from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import os, time
from pathlib import Path

from crypto_utils import load_private_key, decrypt_seed, load_public_key, sign_message_rsa_pss, encrypt_with_public_key
from totp_utils import generate_totp_code, verify_totp_code

app = FastAPI()

DATA_PATH = Path("/data")
SEED_FILE = DATA_PATH / "seed.txt"

# load keys from app root (they will be copied into container)
STUDENT_PRIVATE = "student_private.pem"
INSTRUCTOR_PUBLIC = "instructor_public.pem"

@app.post("/decrypt-seed")
async def decrypt_seed_endpoint(payload: dict):
    enc = payload.get("encrypted_seed")
    if not enc:
        raise HTTPException(status_code=400, detail={"error": "Missing encrypted_seed"})
    try:
        private_key = load_private_key(STUDENT_PRIVATE)
        hex_seed = decrypt_seed(enc, private_key)
        DATA_PATH.mkdir(parents=True, exist_ok=True)
        with open(SEED_FILE, "w") as f:
            f.write(hex_seed)
        # set permissions
        os.chmod(SEED_FILE, 0o600)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})

@app.get("/generate-2fa")
async def generate_2fa():
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})
    with open(SEED_FILE, "r") as f:
        hex_seed = f.read().strip()
    try:
        code = generate_totp_code(hex_seed)
        # remaining seconds in current 30s period
        valid_for = 30 - (int(time.time()) % 30)
        return {"code": code, "valid_for": valid_for}
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "TOTP generation failed"})

class VerifyPayload(BaseModel):
    code: str

@app.post("/verify-2fa")
async def verify_2fa(payload: VerifyPayload):
    code = payload.code
    if not code:
        raise HTTPException(status_code=400, detail={"error": "Missing code"})
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})
    with open(SEED_FILE, "r") as f:
        hex_seed = f.read().strip()
    valid = verify_totp_code(hex_seed, code, valid_window=1)
    return {"valid": valid}

@app.get("/health")
async def health():
    return {"status":"ok"}
