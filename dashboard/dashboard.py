import os
import streamlit as st
import pandas as pd
from joblib import load
import json
from datetime import datetime

# --- App Title ---
st.title("User Behaviour Risk Dashboard (Real-Time)")

# --- Base directory ---
base_dir = os.path.expanduser("~/user_behaviour_monitor")

# --- Paths ---
model_path = os.path.join(base_dir, "models", "user_behavior_model.joblib")
log_path = os.path.join(base_dir, "logs", "events.json")

# --- Load model ---
model = load(model_path)
st.success("Model loaded successfully.")

# --- Load logs ---
if not os.path.exists(log_path):
    st.warning("No logs found yet.")
    st.stop()

with open(log_path, "r") as f:
    logs = json.load(f)

if len(logs) == 0:
    st.warning("Logs are empty.")
    st.stop()

# Convert to DataFrame
df = pd.DataFrame(logs)

# --- Feature Engineering ---
def extract_features(df):
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['login_hour'] = df['timestamp'].dt.hour

    # Basic approximations (can improve later)
    df['files_accessed'] = df['action'].apply(lambda x: 1 if "accessed" in x else 0)
    df['commands_executed'] = 0
    df['session_duration'] = 0
    df['failed_logins'] = df['status'].apply(lambda x: 1 if x == "ALERT" else 0)

    return df

df = extract_features(df)

# --- Aggregate per user ---
user_df = df.groupby("user").agg({
    "login_hour": "mean",
    "files_accessed": "sum",
    "commands_executed": "sum",
    "session_duration": "sum",
    "failed_logins": "sum"
}).reset_index()

# --- ML Prediction ---
features = ['login_hour', 'files_accessed', 'commands_executed', 'session_duration', 'failed_logins']
X = user_df[features]

user_df['anomaly'] = model.predict(X)

# --- Risk Score ---
def calculate_risk(row):
    score = 0
    if row["login_hour"] < 6 or row["login_hour"] > 22:
        score += 30
    if row["files_accessed"] > 20:
        score += 25
    if row["failed_logins"] > 2:
        score += 20
    if row["anomaly"] == -1:
        score += 25
    return score

user_df['risk_score'] = user_df.apply(calculate_risk, axis=1)
user_df['status'] = user_df['risk_score'].apply(lambda x: "ALERT" if x > 70 else "NORMAL")

# --- Summary ---
normal_count = sum(user_df['status'] == 'NORMAL')
alert_count = sum(user_df['status'] == 'ALERT')
total_users = len(user_df)
alert_percentage = alert_count / total_users if total_users > 0 else 0

st.subheader("Risk Summary")
st.write(f"Total users: {total_users}")
st.write(f"Normal users: {normal_count}")
st.write(f"Alert users: {alert_count}")
st.progress(alert_percentage)

# --- Highlight alerts ---
def highlight_alert(row):
    return ['background-color: red; color: white' if row.status == 'ALERT' else '' for _ in row]

# --- Table ---
st.subheader("User Risk Table")
st.dataframe(
    user_df[['user', 'risk_score', 'status']]
    .sort_values(by='risk_score', ascending=False)
    .style.apply(highlight_alert, axis=1)
)

# --- Live event feed ---
st.subheader("Live Event Logs")
st.dataframe(df[['timestamp', 'user', 'action', 'status']].sort_values(by='timestamp', ascending=False))
