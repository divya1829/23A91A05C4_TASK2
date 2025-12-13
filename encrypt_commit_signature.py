import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# CHANGE THIS to your commit hash
COMMIT_HASH = "45c44bc61d8e80f8974cd0bce11e030153c0c520"

# Load student private key
with open("student_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

# Sign commit hash (ASCII)
signature = private_key.sign(
    COMMIT_HASH.encode("utf-8"),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Load instructor public key
with open("instructor_public.pem", "rb") as f:
    instructor_public = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

# Encrypt signature
encrypted_signature = instructor_public.encrypt(
    signature,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Base64 encode
encoded = base64.b64encode(encrypted_signature).decode()

# Save output
with open("encrypted_signature.txt", "w") as f:
    f.write(encoded)

print("✅ Encrypted commit signature generated")
print(encoded)
