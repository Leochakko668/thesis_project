import os
import json
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
from joblib import load
from supabase import create_client
from datetime import datetime

st.set_page_config(
    page_title="User Behaviour Monitor",
    page_icon="🔐",
    layout="wide"
)

st.markdown("""
<style>
    .block-container { padding-top: 1.5rem; }
    .section-label {
        font-size: 10px;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: #888;
        border-bottom: 1px solid #eee;
        padding-bottom: 0.5rem;
        margin-bottom: 1rem;
    }
    div[data-testid="stMetric"] {
        border: 1px solid #eee;
        border-radius: 2px;
        padding: 1rem;
    }
    div[data-testid="stMetric"] label {
        font-size: 10px !important;
        letter-spacing: 0.12em !important;
        text-transform: uppercase !important;
        color: #888 !important;
    }
</style>
""", unsafe_allow_html=True)

SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]

BASE_DIR = os.path.expanduser("~/user_behaviour_monitor")
IF_MODEL_FILE = os.path.join(BASE_DIR, "models", "user_behavior_model.joblib")
LOF_MODEL_FILE = os.path.join(BASE_DIR, "models", "user_behavior_lof.joblib")

@st.cache_resource
def init_supabase():
    return create_client(SUPABASE_URL, SUPABASE_KEY)

@st.cache_resource
def load_models():
    if_model = load(IF_MODEL_FILE)
    lof_model = load(LOF_MODEL_FILE)
    return if_model, lof_model

@st.cache_data(ttl=10)
def load_logs():
    try:
        db = init_supabase()
        response = db.table("events")\
            .select("*")\
            .order("timestamp", desc=True)\
            .limit(500)\
            .execute()
        return response.data
    except Exception as e:
        st.error(f"Could not load logs: {e}")
        return []

supabase = init_supabase()
if_model, lof_model = load_models()
logs = load_logs()
logs_df = pd.DataFrame(logs) if logs else pd.DataFrame()

col_title, col_status = st.columns([3,1])
with col_title:
    st.markdown("## 🔐 User Behaviour Monitor")
    st.markdown("<p style='color:#888;margin-top:-10px;font-size:13px;letter-spacing:0.05em;'>Institution security — real-time anomaly detection</p>", unsafe_allow_html=True)
with col_status:
    st.markdown("<br>", unsafe_allow_html=True)
    st.success("● Live")

st.markdown("---")

if not logs_df.empty:
    logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'])
    agg_df = logs_df.groupby('user').agg({
        'action': 'count',
        'status': lambda x: sum(1 for s in x if s == 'ALERT')
    }).rename(columns={'action':'actions_total','status':'alerts_total'}).reset_index()

    features_list = []
    for _, row in agg_df.iterrows():
        user_logs = logs_df[logs_df['user'] == row['user']]
        avg_hour = int(user_logs['timestamp'].dt.hour.mean()) if not user_logs.empty else 12
        features_list.append({
            'login_hour': avg_hour,
            'files_accessed': row['actions_total'],
            'commands_executed': 0,
            'session_duration': 0,
            'failed_logins': row['alerts_total']
        })

    features_df = pd.DataFrame(features_list)
    agg_df['if_prediction'] = if_model.predict(features_df)
    agg_df['lof_prediction'] = lof_model.predict(features_df)

    def calculate_risk(row):
        score = 0
        if row['if_prediction'] == -1: score += 25
        if row['lof_prediction'] == -1: score += 25
        if row['alerts_total'] > 2: score += 25
        if row['actions_total'] > 20: score += 25
        return score

    agg_df['risk_score'] = agg_df.apply(calculate_risk, axis=1)
    agg_df['status'] = agg_df['risk_score'].apply(lambda x: 'ALERT' if x > 50 else 'NORMAL')
    agg_df['IF Status'] = agg_df['if_prediction'].map({1:'Normal',-1:'Anomaly'})
    agg_df['LOF Status'] = agg_df['lof_prediction'].map({1:'Normal',-1:'Anomaly'})

    total_users = len(agg_df)
    normal_count = sum(agg_df['status'] == 'NORMAL')
    alert_count = sum(agg_df['status'] == 'ALERT')
    total_events = len(logs_df)
else:
    agg_df = pd.DataFrame()
    total_users = normal_count = alert_count = total_events = 0

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Users", total_users)
m2.metric("Normal", normal_count)
m3.metric("Alerts", alert_count)
m4.metric("Events Today", total_events)

st.markdown("<br>", unsafe_allow_html=True)

c1, c2, c3 = st.columns([1,1,2])

with c1:
    st.markdown('<p class="section-label">Risk distribution</p>', unsafe_allow_html=True)
    if total_users > 0:
        fig, ax = plt.subplots(figsize=(3.5,3))
        ax.pie([normal_count, alert_count],
               labels=['Normal','Alert'],
               colors=['#3B6D11','#A32D2D'],
               autopct='%1.0f%%',
               wedgeprops=dict(width=0.6),
               startangle=90)
        for text in ax.texts: text.set_fontsize(10)
        fig.patch.set_alpha(0)
        st.pyplot(fig)
    else:
        st.info("No data yet")

with c2:
    st.markdown('<p class="section-label">Event types</p>', unsafe_allow_html=True)
    if not logs_df.empty:
        action_counts = {}
        for action in logs_df['action']:
            if 'login_success' in str(action): action_counts['Login'] = action_counts.get('Login',0)+1
            elif 'login_attempt' in str(action): action_counts['Failed'] = action_counts.get('Failed',0)+1
            elif 'logout' in str(action): action_counts['Logout'] = action_counts.get('Logout',0)+1
            elif 'accessed' in str(action): action_counts['File access'] = action_counts.get('File access',0)+1
            else: action_counts['Other'] = action_counts.get('Other',0)+1
        fig2, ax2 = plt.subplots(figsize=(3.5,3))
        ax2.pie(list(action_counts.values()),
                labels=list(action_counts.keys()),
                colors=['#1D9E75','#A32D2D','#5F5E5A','#185FA5','#854F0B'],
                autopct='%1.0f%%',
                wedgeprops=dict(width=0.6),
                startangle=90)
        for text in ax2.texts: text.set_fontsize(9)
        fig2.patch.set_alpha(0)
        st.pyplot(fig2)
    else:
        st.info("No data yet")

with c3:
    st.markdown('<p class="section-label">Weekly activity</p>', unsafe_allow_html=True)
    if not logs_df.empty:
        logs_df['date'] = logs_df['timestamp'].dt.strftime('%a %d %b')
        daily = logs_df.groupby(['date','status']).size().unstack(fill_value=0).reset_index()
        if 'ALERT' not in daily.columns: daily['ALERT'] = 0
        if 'NORMAL' not in daily.columns: daily['NORMAL'] = 0
        fig3, ax3 = plt.subplots(figsize=(6,3))
        x = range(len(daily))
        ax3.bar(x, daily['NORMAL'], label='Normal', color='#3B6D11', alpha=0.9)
        ax3.bar(x, daily['ALERT'], bottom=daily['NORMAL'], label='Alert', color='#A32D2D', alpha=0.9)
        ax3.set_xticks(list(x))
        ax3.set_xticklabels(daily['date'], fontsize=9)
        ax3.legend(fontsize=9)
        ax3.spines['top'].set_visible(False)
        ax3.spines['right'].set_visible(False)
        fig3.patch.set_alpha(0)
        st.pyplot(fig3)
    else:
        st.info("No data yet")

st.markdown("<br>", unsafe_allow_html=True)
st.markdown('<p class="section-label">User risk table</p>', unsafe_allow_html=True)

if not agg_df.empty:
    display_df = agg_df[['user','risk_score','IF Status','LOF Status','alerts_total','actions_total','status']].sort_values('risk_score', ascending=False).copy()
    display_df.columns = ['User','Risk Score','IF Model','LOF Model','Alert Events','Total Actions','Status']

    def highlight_rows(row):
        if row['Status'] == 'ALERT':
            return ['background-color:#fff0f0;color:#a32d2d']*len(row)
        return ['background-color:#f0fff4;color:#27500a']*len(row)

    st.dataframe(
        display_df.style.apply(highlight_rows, axis=1),
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No users logged yet")

st.markdown("<br>", unsafe_allow_html=True)
st.markdown('<p class="section-label">Event log</p>', unsafe_allow_html=True)

if not logs_df.empty:
    f1, f2, f3, f4, f5 = st.columns([2,2,1,1,1])
    with f1:
        search = st.text_input("", placeholder="Search user or file...", label_visibility="collapsed")
    with f2:
        status_filter = st.selectbox("", ["All statuses","ALERT","NORMAL"], label_visibility="collapsed")
    with f3:
        time_from = st.time_input("From", value=datetime.strptime("00:00","%H:%M").time(), label_visibility="visible")
    with f4:
        time_to = st.time_input("To", value=datetime.strptime("23:59","%H:%M").time(), label_visibility="visible")
    with f5:
        csv = logs_df[['timestamp','user','action','status']].to_csv(index=False)
        st.download_button("Download CSV", csv, "logs.csv", "text/csv")

    filtered = logs_df.copy()
    if search:
        filtered = filtered[
            filtered['user'].str.contains(search, case=False, na=False) |
            filtered['action'].str.contains(search, case=False, na=False)
        ]
    if status_filter != "All statuses":
        filtered = filtered[filtered['status'] == status_filter]

    filtered = filtered[
        (filtered['timestamp'].dt.time >= time_from) &
        (filtered['timestamp'].dt.time <= time_to)
    ]

    filtered = filtered.sort_values('timestamp', ascending=False)
    st.caption(f"{len(filtered)} events found")

    def highlight_logs(row):
        if row['status'] == 'ALERT':
            return ['background-color:#fff0f0;color:#a32d2d']*len(row)
        return ['background-color:#f0fff4;color:#27500a']*len(row)

    st.dataframe(
        filtered[['timestamp','user','action','status']].style.apply(highlight_logs, axis=1),
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No logs yet")

st.markdown("---")
st.markdown("<p style='text-align:center;color:#aaa;font-size:11px;letter-spacing:0.08em;'>USER BEHAVIOUR MONITOR — THESIS PROJECT — RASPBERRY PI SOC SYSTEM</p>", unsafe_allow_html=True)