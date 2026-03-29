import pandas as pd
from sklearn.ensemble import IsolationForest
from joblib import dump

print("Loading dataset...")

# Load dataset
data = pd.read_csv("data/user_activity.csv")

# Features for model (no user_id to simplify joblib loading)
X = data[['login_hour', 'files_accessed', 'commands_executed', 'session_duration', 'failed_logins']]

print("Training model...")

# Train Isolation Forest
model = IsolationForest(contamination=0.05, random_state=42)
model.fit(X)

print("Saving model...")

# Save model safely with joblib
dump(model, "models/user_behavior_model.joblib")

print("Model trained and saved successfully with joblib.")
