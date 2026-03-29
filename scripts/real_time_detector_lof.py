import subprocess
import pandas as pd
from joblib import load
from datetime import datetime

print("Starting real-time security detection with IF + LOF...\n")

# Load models
if_model = load("../models/user_behavior_model.joblib")
lof_model = load("../models/user_behavior_lof.joblib")

# Start real-time log monitoring
process = subprocess.Popen(
    ["journalctl", "-f"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

failed_logins = 0

for line in process.stdout:
    line = line.strip()

    # Detect sudo commands (example trigger)
    if "sudo[" in line:
        now = datetime.now()

        # Collect features for prediction
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

        # Predict anomalies with both models
        if_pred = if_model.predict(features)[0]
        lof_pred = lof_model.predict(features)[0]

        # Output based on detection
        if if_pred == -1 and lof_pred == -1:
            print("? Both models detect anomaly")
            print(line)
        elif if_pred == -1:
            print("?? IF detects anomaly only")
            print(line)
        elif lof_pred == -1:
            print("?? LOF detects anomaly only")
            print(line)
        else:
            print("Normal activity")
            print(line)
