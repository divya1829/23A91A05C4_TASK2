import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# 1. Load private key
with open("student_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# 2. Load encrypted seed
with open("encrypted_seed.txt", "r") as f:
    encrypted_b64 = f.read().strip()

encrypted_bytes = base64.b64decode(encrypted_b64)

# 3. Decrypt using RSA OAEP SHA-256
decrypted = private_key.decrypt(
    encrypted_bytes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# 4. Convert to string
seed = decrypted.decode("utf-8")

# 5. Validate
assert len(seed) == 64
assert all(c in "0123456789abcdef" for c in seed)

# 6. Save decrypted seed
with open("seed.txt", "w") as f:
    f.write(seed)

print("✅ Decrypted seed saved to seed.txt")
print("Seed:", seed)
