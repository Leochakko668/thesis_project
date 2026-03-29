import pandas as pd
from sklearn.neighbors import LocalOutlierFactor
from joblib import dump

print("Loading dataset...")
data = pd.read_csv("../data/user_activity.csv")

# Features for LOF
X = data[['login_hour', 'files_accessed', 'commands_executed', 'session_duration', 'failed_logins']]

# LOF model (unsupervised)
# Note: novelty=True allows using LOF for predicting new unseen data
lof_model = LocalOutlierFactor(n_neighbors=20, contamination=0.05, novelty=True)

print("Training LOF model...")
lof_model.fit(X)

print("Saving LOF model...")
dump(lof_model, "../models/user_behavior_lof.joblib")
print("LOF trained and saved successfully.")
