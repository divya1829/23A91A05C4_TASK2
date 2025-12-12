import base64, pyotp, time

def hex_to_base32(hex_seed: str) -> str:
    seed_bytes = bytes.fromhex(hex_seed)
    b32 = base64.b32encode(seed_bytes).decode('utf-8')
    return b32

def generate_totp_code(hex_seed: str) -> str:
    b32 = hex_to_base32(hex_seed)
    t = pyotp.TOTP(b32, digits=6, interval=30)   # SHA1 default
    return t.now()

def verify_totp_code(hex_seed: str, code: str, valid_window:int=1) -> bool:
    b32 = hex_to_base32(hex_seed)
    t = pyotp.TOTP(b32, digits=6, interval=30)
    return t.verify(code, valid_window=valid_window)
