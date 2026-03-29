import os
import json
from cryptography.fernet import Fernet

BASE_DIR = os.path.expanduser("~/user_behaviour_monitor")
KEY_FILE = os.path.join(BASE_DIR, "models", "encryption.key")
LOG_FILE = os.path.join(BASE_DIR, "logs", "events.json")

# Load key
with open(KEY_FILE, "rb") as f:
    key = f.read()

fernet = Fernet(key)

# Test data
data = {"message": "hello this is encrypted"}

# Encrypt and save
encrypted = fernet.encrypt(json.dumps(data).encode())

with open(LOG_FILE, "wb") as f:
    f.write(encrypted)

print("Encrypted and saved.")

# Read and decrypt
with open(LOG_FILE, "rb") as f:
    encrypted_data = f.read()

decrypted = json.loads(fernet.decrypt(encrypted_data))

print("Decrypted data:", decrypted)
