import subprocess
import pandas as pd
from joblib import load
from datetime import datetime

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

    # Detect sudo commands
    if "sudo[" in line:

        now = datetime.now()

        login_hour = now.hour
        files_accessed = 1
        commands_executed = 1
        session_duration = 1

        features = pd.DataFrame([{
            "login_hour": login_hour,
            "files_accessed": files_accessed,
            "commands_executed": commands_executed,
            "session_duration": session_duration,
            "failed_logins": failed_logins
        }])

        prediction = model.predict(features)[0]

        if prediction == -1:
            print("??  ANOMALY DETECTED")
            print(line)
        else:
            print("Normal sudo activity")
            print(line)
