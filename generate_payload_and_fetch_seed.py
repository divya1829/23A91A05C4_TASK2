import json
import base64
import requests

API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"
STUDENT_ID = "23A91A05C5"
GIT_REPO = "https://github.com/divya1829/23A91A05C4_TASK2"

# Read student public key
with open("student_public.pem", "r") as f:
    public_key = f.read()

# Build payload
payload = {
    "student_id": STUDENT_ID,
    "github_repo_url": GIT_REPO,
    "public_key": public_key
}

# Save payload.json (optional)
with open("payload.json", "w") as f:
    json.dump(payload, f, indent=2)

print("📌 Sending request to instructor API...")

# Send request
response = requests.post(API_URL, json=payload)

# Save full response
with open("seed_response.json", "w") as f:
    f.write(response.text)

print("📌 Response saved to seed_response.json")

# Extract encrypted seed
try:
    encrypted_seed = response.json()["encrypted_seed"]
    with open("encrypted_seed.txt", "w") as f:
        f.write(encrypted_seed)

    print("✅ Encrypted seed saved to encrypted_seed.txt")
except Exception as e:
    print("❌ Failed to extract encrypted seed:", e)
