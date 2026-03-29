import subprocess
import pandas as pd
from joblib import load
from datetime import datetime
from alert_email import send_alert

print("Starting real-time security detection...\n")
model = load("../models/user_behavior_model.joblib")

process = subprocess.Popen(
    ["journalctl", "-f"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

failed_logins = 0

for line in process.stdout:
    line = line.strip()
    if "sudo[" in line:
        now = datetime.now()
        features = pd.DataFrame([{
            "login_hour": now.hour,
            "files_accessed": 1,
            "commands_executed": 1,
            "session_duration": 1,
            "failed_logins": failed_logins
        }])
        prediction = model.predict(features)[0]
        if prediction == -1:
            print("ANOMALY DETECTED")
            print(line)
            send_alert(
                user="system",
                reason="Suspicious sudo command detected in real-time",
                details=line
            )
        else:
            print("Normal sudo activity")
            print(line)