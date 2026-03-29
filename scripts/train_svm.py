import pandas as pd
from sklearn.svm import OneClassSVM
from joblib import dump

print("Loading dataset...")
data = pd.read_csv("../data/user_activity.csv")

# Features for SVM
X = data[['login_hour', 'files_accessed', 'commands_executed', 'session_duration', 'failed_logins']]

# Safe kernel selection
if len(X) < 50:
    print("Dataset small ? using linear kernel for SVM")
    svm_model = OneClassSVM(kernel='linear', nu=0.05)
else:
    print("Dataset large enough ? using RBF kernel for SVM")
    svm_model = OneClassSVM(kernel='rbf', gamma='auto', nu=0.05)

print("Training One-Class SVM...")
svm_model.fit(X)

print("Saving SVM model...")
dump(svm_model, "../models/user_behavior_svm.joblib")
print("SVM trained and saved successfully.")
