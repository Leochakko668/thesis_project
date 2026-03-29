import os
import json
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
from joblib import load
from cryptography.fernet import Fernet

# --- Base directory ---
BASE_DIR = os.path.expanduser("~/user_behaviour_monitor")
LOG_FILE = os.path.join(BASE_DIR, "logs", "events.json")
IF_MODEL_FILE = os.path.join(BASE_DIR, "models", "user_behavior_model.joblib")
LOF_MODEL_FILE = os.path.join(BASE_DIR, "models", "user_behavior_lof.joblib")
KEY_FILE = os.path.join(BASE_DIR, "models", "encryption.key")

# --- Load models ---
if_model = load(IF_MODEL_FILE)
st.success("Isolation Forest model loaded")

lof_model = load(LOF_MODEL_FILE)
st.success("LOF model loaded")

# --- Load encryption key ---
with open(KEY_FILE, "rb") as f:
    key = f.read()
fernet = Fernet(key)

# --- Load logs ---
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

# --- Process data ---
if not logs_df.empty:
    logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'])

    agg_df = logs_df.groupby('user').agg({
        'action': 'count',
        'status': lambda x: sum(1 for s in x if s == 'ALERT')
    }).rename(columns={
        'action': 'actions_total',
        'status': 'alerts_total'
    }).reset_index()

    # --- ML features ---
    features = []
    for _, row in agg_df.iterrows():
        features.append({
            'login_hour': 12,
            'files_accessed': row['actions_total'],
            'commands_executed': 0,
            'session_duration': 0,
            'failed_logins': row['alerts_total']
        })
    features_df = pd.DataFrame(features)

    # --- Predict ---
    agg_df['if_prediction'] = if_model.predict(features_df)
    agg_df['lof_prediction'] = lof_model.predict(features_df)

    # --- Risk score ---
    def calculate_risk(row):
        score = 0
        if row['if_prediction'] == -1:
            score += 25
        if row['lof_prediction'] == -1:
            score += 25
        if row['alerts_total'] > 2:
            score += 25
        if row['actions_total'] > 20:
            score += 25
        return score

    agg_df['risk_score'] = agg_df.apply(calculate_risk, axis=1)
    agg_df['status'] = agg_df['risk_score'].apply(lambda x: 'ALERT' if x > 50 else 'NORMAL')

else:
    agg_df = pd.DataFrame(columns=[
        'user','actions_total','alerts_total','if_prediction','lof_prediction',
        'risk_score','status'
    ])

# --- UI ---
st.title("User Behaviour Risk Dashboard")

# --- Summary ---
normal_count = sum(agg_df['status'] == 'NORMAL')
alert_count = sum(agg_df['status'] == 'ALERT')
total_users = len(agg_df)

st.write(f"Total users: {total_users}")
st.write(f"Normal users: {normal_count}")
st.write(f"Alert users: {alert_count}")

if total_users > 0:
    st.progress(alert_count / total_users)

    fig, ax = plt.subplots()
    ax.pie([normal_count, alert_count],
           labels=['NORMAL','ALERT'],
           autopct='%1.1f%%',
           colors=['green','red'])
    st.pyplot(fig)

# --- Table ---
st.subheader("User Risk Table")

def highlight(row):
    return ['background-color: red; color: white' if row.status == 'ALERT' else '' for _ in row]

# Map predictions to human-readable
agg_df['IF Status'] = agg_df['if_prediction'].map({1: 'Normal', -1: 'Anomaly'})
agg_df['LOF Status'] = agg_df['lof_prediction'].map({1: 'Normal', -1: 'Anomaly'})

st.dataframe(
    agg_df.sort_values(by='risk_score', ascending=False).style.apply(highlight, axis=1)
)

# --- Logs ---
st.subheader("Detailed Logs")

if not logs_df.empty:
    logs_df = logs_df.sort_values(by='timestamp', ascending=False)
    st.dataframe(logs_df[['timestamp','user','action','status']])
else:
    st.write("No logs yet")