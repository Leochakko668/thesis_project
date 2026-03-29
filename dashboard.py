# dashboard.py
import os
import json
import pandas as pd
import streamlit as st
from joblib import load
from cryptography.fernet import Fernet
import matplotlib.pyplot as plt

# --- Base directory ---
BASE_DIR = os.path.expanduser("~/user_behaviour_monitor")
USERS_FILE = os.path.join(BASE_DIR, "data", "users.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "events.json")
MODEL_FILE = os.path.join(BASE_DIR, "models", "user_behavior_model.joblib")
KEY_FILE = os.path.join(BASE_DIR, "models", "encryption.key")

# --- Load ML model ---
model = load(MODEL_FILE)
st.success("ML model loaded successfully.")

# --- Load encryption key ---
with open(KEY_FILE, "rb") as f:
    key = f.read()
fernet = Fernet(key)

# --- Load users ---
with open(USERS_FILE, "r") as f:
    users = json.load(f)

# --- Load and decrypt logs ---
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

logs = load_logs()
logs_df = pd.DataFrame(logs)

# --- Prepare User Risk Table ---
if not logs_df.empty:
    # Aggregate per user
    agg_df = logs_df.groupby('user').agg({
        'action': 'count',
        'status': lambda x: sum([1 if s=='ALERT' else 0 for s in x])
    }).rename(columns={'action': 'actions_total', 'status': 'alerts_total'}).reset_index()

    # ML prediction features
    features = []
    for _, row in agg_df.iterrows():
        features.append({
            'login_hour': 12,  # placeholder for simplicity
            'files_accessed': row['actions_total'],
            'commands_executed': 0,
            'session_duration': 0,
            'failed_logins': row['alerts_total']
        })
    features_df = pd.DataFrame(features)
    predictions = model.predict(features_df)
    agg_df['anomaly'] = predictions

    # Risk score
    def calculate_risk(row):
        score = 0
        if row['anomaly'] == -1:
            score += 25
        if row['alerts_total'] > 2:
            score += 20
        if row['actions_total'] > 20:
            score += 25
        return score

    agg_df['risk_score'] = agg_df.apply(calculate_risk, axis=1)
    agg_df['status'] = agg_df['risk_score'].apply(lambda x: 'ALERT' if x>50 else 'NORMAL')
else:
    agg_df = pd.DataFrame(columns=['user','actions_total','alerts_total','anomaly','risk_score','status'])

# --- Streamlit App ---
st.title("User Behaviour Risk Dashboard")

# --- Summary ---
st.subheader("Risk Summary")
normal_count = sum(agg_df['status']=='NORMAL')
alert_count = sum(agg_df['status']=='ALERT')
total_users = len(agg_df)
alert_percentage = alert_count/total_users if total_users>0 else 0

st.write(f"Total users: {total_users}")
st.write(f"Normal users: {normal_count}")
st.write(f"Alert users: {alert_count}")
st.progress(alert_percentage)

# --- Pie chart ---
if total_users > 0:
    fig, ax = plt.subplots()
    ax.pie([normal_count, alert_count], labels=['NORMAL','ALERT'], autopct='%1.1f%%', colors=['green','red'])
    ax.set_title("User Risk Distribution")
    st.pyplot(fig)

# --- User Risk Table ---
st.subheader("User Risk Table")
def highlight_alert(row):
    return ['background-color: red; color: white' if row.status=='ALERT' else '' for _ in row]

st.dataframe(
    agg_df[['user','risk_score','status']].sort_values(by='risk_score', ascending=False).style.apply(highlight_alert, axis=1)
)

# --- Detailed Event Logs ---
st.subheader("Detailed Event Logs")
if not logs_df.empty:
    logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'])
    logs_df = logs_df.sort_values(by='timestamp', ascending=False)

    def highlight_alert_events(row):
        return ['background-color: red; color: white' if row.status=='ALERT' else '' for _ in row]

    st.dataframe(
        logs_df[['timestamp','user','action','status']].style.apply(highlight_alert_events, axis=1)
    )
else:
    st.write("No events logged yet.")