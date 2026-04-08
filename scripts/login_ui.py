import json
import os
import uuid
import streamlit as st
from datetime import datetime
from cryptography.fernet import Fernet
from supabase import create_client

st.set_page_config(
    page_title="User Behaviour Monitor — Login",
    page_icon="🔐",
    layout="centered"
)

st.markdown("""
<style>
    .block-container { padding-top: 2rem; max-width: 480px; }
    .brand { font-size: 10px; letter-spacing: 0.16em; text-transform: uppercase; color: #888; margin-bottom: 6px; }
    .title { font-size: 26px; font-weight: 500; margin: 0 0 2rem; }
    .section-label {
        font-size: 10px; letter-spacing: 0.14em;
        text-transform: uppercase; color: #888;
        border-bottom: 1px solid #eee;
        padding-bottom: 0.5rem; margin-bottom: 1rem;
    }
    .log-item {
        display: flex; justify-content: space-between;
        align-items: center; padding: 8px 0;
        border-bottom: 1px solid #f0f0f0; font-size: 13px;
    }
    .badge {
        font-size: 10px; letter-spacing: 0.06em;
        padding: 2px 10px; border-radius: 2px;
        text-transform: uppercase;
    }
    .badge-alert { background:#fff0f0; color:#a32d2d; }
    .badge-normal { background:#f0fff4; color:#27500a; }
    .stButton > button {
        width: 100%; border-radius: 2px !important;
        font-size: 12px !important; letter-spacing: 0.1em !important;
        text-transform: uppercase !important;
    }
    div[data-testid="stTabs"] button {
        font-size: 10px !important; letter-spacing: 0.12em !important;
        text-transform: uppercase !important;
    }
</style>
""", unsafe_allow_html=True)

BASE_DIR = os.path.expanduser("~/user_behaviour_monitor")
USERS_FILE = os.path.join(BASE_DIR, "data", "users.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "events.json")
KEY_FILE = os.path.join(BASE_DIR, "models", "encryption.key")

SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]

@st.cache_resource
def init_supabase():
    return create_client(SUPABASE_URL, SUPABASE_KEY)

@st.cache_resource
def init_fernet():
    with open(KEY_FILE, "rb") as f:
        key = f.read()
    return Fernet(key)

supabase = init_supabase()
fernet = init_fernet()

def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

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
    except Exception as e:
        pass
    try:
        from alert_email import send_alert
        if status == "ALERT":
            send_alert(user, action, f"Status: {status}")
    except:
        pass

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "current_role" not in st.session_state:
    st.session_state.current_role = None
if "session_log" not in st.session_state:
    st.session_state.session_log = []

if not st.session_state.logged_in:
    st.markdown('<p class="brand">Institution security</p>', unsafe_allow_html=True)
    st.markdown('<h1 class="title">User behaviour monitor</h1>', unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["Login", "Create user"])

    with tab1:
        st.markdown("<br>", unsafe_allow_html=True)
        username = st.text_input("Username", placeholder="Enter username")
        password = st.text_input("Password", placeholder="Enter password", type="password")
        st.markdown("<br>", unsafe_allow_html=True)

        if st.button("Login"):
            if not username or not password:
                st.error("Please enter both username and password")
            else:
                users = load_users()
                matched = next(
                    (u for u in users if u["username"] == username and u["password"] == password),
                    None
                )
                if matched:
                    st.session_state.logged_in = True
                    st.session_state.current_user = username
                    st.session_state.current_role = matched["role"]
                    st.session_state.session_log = []
                    log_event(username, "login_success", "NORMAL")
                    st.rerun()
                else:
                    log_event(username, "login_attempt", "ALERT")
                    st.error("Invalid credentials — IT admin has been notified")

    with tab2:
        st.markdown("<br>", unsafe_allow_html=True)
        new_username = st.text_input("New username", placeholder="Choose a username")
        new_password = st.text_input("New password", placeholder="Choose a password", type="password")
        new_role = st.selectbox("Role", ["user", "it_admin"])
        admin_code = st.text_input("Admin authorisation code", placeholder="Required to create users", type="password")
        st.markdown("<br>", unsafe_allow_html=True)

        if st.button("Create user"):
            if admin_code != "admin123":
                st.error("Invalid authorisation code")
            elif not new_username or not new_password:
                st.error("Please fill in all fields")
            else:
                users = load_users()
                if any(u["username"] == new_username for u in users):
                    st.error(f"Username '{new_username}' already exists")
                else:
                    users.append({
                        "username": new_username,
                        "password": new_password,
                        "role": new_role
                    })
                    save_users(users)
                    log_event("system", f"new user created: {new_username}", "NORMAL")
                    st.success(f"User '{new_username}' created successfully!")

else:
    username = st.session_state.current_user
    role = st.session_state.current_role

    col1, col2 = st.columns([3,1])
    with col1:
        st.markdown('<p class="brand">Institution security</p>', unsafe_allow_html=True)
        st.markdown('<h1 class="title">User behaviour monitor</h1>', unsafe_allow_html=True)
    with col2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        if st.button("Logout"):
            log_event(username, "logout", "NORMAL")
            st.session_state.logged_in = False
            st.session_state.current_user = None
            st.session_state.current_role = None
            st.session_state.session_log = []
            st.rerun()

    st.markdown("---")

    role_color = "#3B6D11" if role == "it_admin" else "#185FA5"
    st.markdown(
        f"Welcome, <strong>{username}</strong> &nbsp;|&nbsp; "
        f"<span style='color:{role_color};font-size:11px;letter-spacing:0.1em;text-transform:uppercase;'>{role}</span>",
        unsafe_allow_html=True
    )

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<p class="section-label">File access</p>', unsafe_allow_html=True)

    AVAILABLE_FILES = [
        "report.pdf", "notes.txt", "budget.xlsx",
        "policy.docx", "secret.txt", "config.json", "logs.csv"
    ]

    col_file, col_btn = st.columns([3,1])
    with col_file:
        file_choice = st.selectbox(
            "",
            AVAILABLE_FILES,
            label_visibility="collapsed"
        )
    with col_btn:
        access_clicked = st.button("Access file")

    if access_clicked:
        if file_choice == "secret.txt" and role != "it_admin":
            st.error(f"Access denied — you do not have permission to access '{file_choice}'")
            log_event(username, f"accessed {file_choice}", "ALERT")
            entry = {"time": datetime.now().strftime("%H:%M:%S"), "file": file_choice, "status": "ALERT"}
            st.session_state.session_log.append(entry)
        else:
            st.success(f"Access granted — '{file_choice}' opened successfully")
            log_event(username, f"accessed {file_choice}", "NORMAL")
            entry = {"time": datetime.now().strftime("%H:%M:%S"), "file": file_choice, "status": "NORMAL"}
            st.session_state.session_log.append(entry)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<p class="section-label">Session activity</p>', unsafe_allow_html=True)

    if st.session_state.session_log:
        for entry in reversed(st.session_state.session_log):
            is_alert = entry["status"] == "ALERT"
            badge_class = "badge-alert" if is_alert else "badge-normal"
            st.markdown(
                f'<div class="log-item">'
                f'<span>{entry["file"]}</span>'
                f'<div style="display:flex;align-items:center;gap:12px;">'
                f'<span style="font-size:11px;color:#aaa;">{entry["time"]}</span>'
                f'<span class="badge {badge_class}">{entry["status"]}</span>'
                f'</div></div>',
                unsafe_allow_html=True
            )
    else:
        st.markdown('<p style="font-size:13px;color:#aaa;">No files accessed this session</p>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("---")
    st.markdown(
        "<p style='text-align:center;color:#aaa;font-size:11px;letter-spacing:0.08em;'>"
        "USER BEHAVIOUR MONITOR — THESIS PROJECT — RASPBERRY PI SOC SYSTEM</p>",
        unsafe_allow_html=True
    )