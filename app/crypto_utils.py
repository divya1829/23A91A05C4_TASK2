from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import base64

# Load private PEM
def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    try:
        ct = base64.b64decode(encrypted_seed_b64)
        plain = private_key.decrypt(
            ct,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        hex_seed = plain.decode("utf-8").strip()
        # Validate: 64 hex chars
        if len(hex_seed) != 64 or any(c not in "0123456789abcdef" for c in hex_seed.lower()):
            raise ValueError("Decrypted seed invalid format")
        return hex_seed.lower()
    except Exception as e:
        raise

def sign_message_rsa_pss(message: str, private_key) -> bytes:
    msg = message.encode("utf-8")
    signature = private_key.sign(
        msg,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    ct = public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ct
