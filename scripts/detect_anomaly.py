import pandas as pd
import joblib

print("Loading trained model...")

model = joblib.load("../models/user_behavior_model.pkl")

print("Model loaded.")

# Example new activity to test
new_data = pd.DataFrame([
    ["alice", 9, 6, 12, 40, 0],
    ["bob", 23, 3, 7, 20, 0],
    ["admin", 3, 100, 150, 200, 5]
], columns=[
    "user",
    "login_hour",
    "files_accessed",
    "commands_executed",
    "session_duration",
    "failed_logins"
])

# Convert user names to numbers
new_data["user_id"] = new_data["user"].astype("category").cat.codes

features = [
    "user_id",
    "login_hour",
    "files_accessed",
    "commands_executed",
    "session_duration",
    "failed_logins"
]

X = new_data[features]

print("Running anomaly detection...")

predictions = model.predict(X)

for i, row in new_data.iterrows():

    result = "ANOMALY" if predictions[i] == -1 else "NORMAL"

    print(f"User {row['user']} ? {result}")
