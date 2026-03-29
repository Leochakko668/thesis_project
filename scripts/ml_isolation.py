import pandas as pd
from sklearn.ensemble import IsolationForest

def train_model(df):
    features = df[['login_hour', 'failed_logins', 'file_access_count']]
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(features)
    return model

def predict_anomaly(model, df):
    features = df[['login_hour', 'failed_logins', 'file_access_count']]
    df['anomaly'] = model.predict(features)
    df['anomaly'] = df['anomaly'].map({1: 0, -1: 1})  # 1 = anomaly
    return df
