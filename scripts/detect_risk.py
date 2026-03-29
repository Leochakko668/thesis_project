import pandas as pd
from joblib import load

print("Loading trained model...")
model = load("models/user_behavior_model.joblib")  # use joblib version
print("Model loaded.")

print("Loading dataset...")
data = pd.read_csv("data/user_activity.csv")

# Use only the features the model was trained on
features = ['login_hour', 'files_accessed', 'commands_executed', 'session_duration', 'failed_logins']
X = data[features]

print("Running anomaly detection...")
predictions = model.predict(X)
data["anomaly"] = predictions

# Risk scoring function
def calculate_risk(row):
    score = 0
    if row["login_hour"] < 6 or row["login_hour"] > 22:  # Late night login
        score += 30
    if row["files_accessed"] > 20:  # Many files accessed
        score += 25
    if row["failed_logins"] > 2:  # Failed logins
        score += 20
    if row["anomaly"] == -1:  # Model flagged anomaly
        score += 25
    return score

data["risk_score"] = data.apply(calculate_risk, axis=1)

print("\nUser Risk Report\n")
for index, row in data.head(20).iterrows():
    status = "ALERT" if row["risk_score"] > 70 else "NORMAL"
    print(f"User: {row['user']} | Risk Score: {row['risk_score']} | Status: {status}")
