import json
import getpass
import os
from datetime import datetime
import uuid
from cryptography.fernet import Fernet

# Paths
BASE_DIR = os.path.expanduser("~/user_behaviour_monitor")
USERS_FILE = os.path.join(BASE_DIR, "data", "users.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "events.json")
KEY_FILE = os.path.join(BASE_DIR, "models", "encryption.key")

# Load encryption key
with open(KEY_FILE, "rb") as f:
    key = f.read()
fernet = Fernet(key)

# Ensure users file exists
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        json.dump([], f)

# Load users
with open(USERS_FILE, "r") as f:
    users = json.load(f)

# Load logs
def load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "rb") as f:
        encrypted_data = f.read()
        if not encrypted_data:
            return []
    try:
        decrypted = fernet.decrypt(encrypted_data)
        return json.loads(decrypted)
    except:
        return []

# Save logs
def save_logs(logs):
    encrypted = fernet.encrypt(json.dumps(logs).encode())
    with open(LOG_FILE, "wb") as f:
        f.write(encrypted)

# Log event
def log_event(user, action, status="NORMAL"):
    logs = load_logs()
    event = {
        "event_id": f"EVT-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}",
        "timestamp": datetime.now().isoformat(),
        "user": user,
        "action": action,
        "status": status
    }
    logs.append(event)
    save_logs(logs)

# --- Interactive menu ---
print("1. Login")
print("2. Create New User")
option = input("Select option (1 or 2): ")

if option == "2":
    new_username = input("Enter new username: ")
    new_password = getpass.getpass("Enter password: ")
    new_role = input("Enter role (it_admin / user): ")
    users.append({"username": new_username, "password": new_password, "role": new_role})
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)
    print(f"? User '{new_username}' created successfully!")
    exit()

# --- Login ---
username = input("Enter username: ")
password = getpass.getpass("Enter password: ")

matched_user = next((u for u in users if u["username"]==username and u["password"]==password), None)

if not matched_user:
    print("? Invalid credentials!")
    log_event(username, "login_attempt", "ALERT")
    exit()

print(f"? Welcome {username} ({matched_user['role']})")
log_event(username, "login_success")

# --- File access loop ---
files_accessed_count = 0
failed_logins_count = 0

while True:
    file_name = input("Enter file (or 'exit'): ")
    login_hour = datetime.now().hour

    if file_name.lower() == "exit":
        log_event(username, "logout")
        print("Logged out.")
        break

    if file_name == "secret.txt" and matched_user["role"] != "it_admin":
        print("? ACCESS DENIED!")
        failed_logins_count += 1
        log_event(username, f"accessed {file_name}", "ALERT")
    else:
        print(f"? Accessed {file_name}")
        files_accessed_count += 1
        log_event(username, f"accessed {file_name}")



