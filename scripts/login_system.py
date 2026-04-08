import json
import getpass
import os
from datetime import datetime
import uuid
from cryptography.fernet import Fernet
from supabase import create_client
import sys
sys.path.append(os.path.expanduser("~/user_behaviour_monitor"))
from supabase_config import SUPABASE_URL, SUPABASE_KEY

BASE_DIR = os.path.expanduser("~/user_behaviour_monitor")
USERS_FILE = os.path.join(BASE_DIR, "data", "users.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "events.json")
KEY_FILE = os.path.join(BASE_DIR, "models", "encryption.key")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

with open(KEY_FILE, "rb") as f:
    key = f.read()
fernet = Fernet(key)

if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        json.dump([], f)

with open(USERS_FILE, "r") as f:
    users = json.load(f)

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

def save_logs(logs):
    encrypted = fernet.encrypt(json.dumps(logs).encode())
    with open(LOG_FILE, "wb") as f:
        f.write(encrypted)

def log_event(user, action, status="NORMAL"):
    event = {
        "event_id": f"EVT-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}",
        "timestamp": datetime.now().isoformat(),
        "user": user,
        "action": action,
        "status": status
    }
    logs = load_logs()
    logs.append(event)
    save_logs(logs)
    try:
        supabase.table("events").insert(event).execute()
        print(f"Event logged to Supabase: {action}")
    except Exception as e:
        print(f"Supabase log failed: {e}")

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
    print(f"User '{new_username}' created successfully!")
    exit()

username = input("Enter username: ")
password = getpass.getpass("Enter password: ")
matched_user = next((u for u in users if u["username"]==username and u["password"]==password), None)

if not matched_user:
    print("Invalid credentials!")
    log_event(username, "login_attempt", "ALERT")
    try:
        from alert_email import send_alert
        send_alert(username, "Failed login attempt", f"User '{username}' entered wrong credentials")
    except Exception as e:
        print(f"Email alert failed: {e}")
    exit()

print(f"Welcome {username} ({matched_user['role']})")
log_event(username, "login_success")

files_accessed_count = 0
failed_logins_count = 0

while True:
    file_name = input("Enter file (or 'exit'): ")
    if file_name.lower() == "exit":
        log_event(username, "logout")
        print("Logged out.")
        break
    if file_name == "secret.txt" and matched_user["role"] != "it_admin":
        print("ACCESS DENIED!")
        failed_logins_count += 1
        log_event(username, f"accessed {file_name}", "ALERT")
        try:
            from alert_email import send_alert
            send_alert(username, "Unauthorised file access", f"User '{username}' tried to access {file_name}")
        except Exception as e:
            print(f"Email alert failed: {e}")
    else:
        print(f"Accessed {file_name}")
        files_accessed_count += 1
        log_event(username, f"accessed {file_name}")