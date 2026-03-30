import os
import json
import time
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
from joblib import load
from cryptography.fernet import Fernet
from datetime import datetime
import csv
import io
from alert_email import send_alert

st.set_page_config(
    page_title="User Behaviour Monitor",
    page_icon="🔐",
    layout="wide"
)

st.markdown("""
<style>
    .block-container { padding-top: 1.5rem; padding-bottom: 1rem; }
    div[data-testid="stMetric"] {
        background: var(--secondary-background-color);
        border-radius: 2px;
        padding: 1rem 1.25rem;
        border: 1px solid rgba(128,128,128,0.15);
    }
    div[data-testid="stMetric"] label {
        font-size: 10px !important;
        letter-spacing: 0.12em !important;
        text-transform: uppercase !important;
        color: grey !important;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        font-size: 32px !important;
        font-weight: 400 !important;
    }
    .section-rule {
        font-size: 10px;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: grey;
        border-bottom: 1px solid rgba(128,128,128,0.2);
        padding-bottom: 0.4rem;
        margin-bottom: 1rem;
        margin-top: 1.5rem;
    }
    .stDataFrame { border-radius: 2px !important; }
    footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

BASE_DIR = os.path.expanduser("~/user_behaviour_monitor")
LOG_FILE  = os.path.join(BASE_DIR, "logs",   "events.json")
IF_MODEL  = os.path.join(BASE_DIR, "models", "user_behavior_model.joblib")
LOF_MODEL = os.path.join(BASE_DIR, "models", "user_behavior_lof.joblib")
KEY_FILE  = os.path.join(BASE_DIR, "models", "encryption.key")

@st.cache_resource
def load_models():
    return load(IF_MODEL), load(LOF_MODEL)

def load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(KEY_FILE, "rb") as f:
        key = f.read()
    fernet = Fernet(key)
    with open(LOG_FILE, "rb") as f:
        data = f.read()
    if not data:
        return []
    try:
        return json.loads(fernet.decrypt(data))
    except:
        return []

if_model, lof_model = load_models()

# --- Auto refresh every 10 seconds ---
st_autorefresh = st.empty()
count = st_autorefresh.empty()
try:
    from streamlit_autorefresh import st_autorefresh as sar
    sar(interval=10000, key="autorefresh")
except:
    pass

# --- Header ---
col_h1, col_h2 = st.columns([4, 1])
with col_h1:
    st.markdown("""
        <p style='font-size:10px;letter-spacing:0.16em;text-transform:uppercase;
        color:grey;margin-bottom:4px;'>Institution security</p>
        <h1 style='font-size:26px;font-weight:500;margin:0;'>
        User Behaviour Monitor</h1>
    """, unsafe_allow_html=True)
with col_h2:
    st.markdown("<br>", unsafe_allow_html=True)
    now = datetime.now().strftime("%d %b %Y  %H:%M")
    st.markdown(f"""
        <div style='text-align:right;font-size:11px;
        color:grey;letter-spacing:0.06em;'>{now}</div>
        <div style='text-align:right;font-size:11px;color:#3B6D11;
        letter-spacing:0.08em;text-transform:uppercase;'>● Live</div>
    """, unsafe_allow_html=True)

st.markdown("<hr style='border:none;border-top:1px solid rgba(128,128,128,0.2);margin:1rem 0;'>",
            unsafe_allow_html=True)

# --- Load and process data ---
logs = load_logs()
logs_df = pd.DataFrame(logs)

if not logs_df.empty:
    logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'])
    logs_df['time_str']  = logs_df['timestamp'].dt.strftime('%H:%M:%S')
    logs_df['date_str']  = logs_df['timestamp'].dt.strftime('%a %d %b')

    agg_df = logs_df.groupby('user').agg(
        actions_total=('action','count'),
        alerts_total=('status', lambda x: sum(1 for s in x if s=='ALERT')),
        last_seen=('timestamp','max')
    ).reset_index()

    features_list = []
    for _, row in agg_df.iterrows():
        user_logs = logs_df[logs_df['user'] == row['user']]
        avg_hour = int(user_logs['timestamp'].dt.hour.mean())
        features_list.append({
            'login_hour':        avg_hour,
            'files_accessed':    row['actions_total'],
            'commands_executed': 0,
            'session_duration':  0,
            'failed_logins':     row['alerts_total']
        })

    features_df = pd.DataFrame(features_list)
    agg_df['if_pred']  = if_model.predict(features_df)
    agg_df['lof_pred'] = lof_model.predict(features_df)

    def calc_risk(row):
        s = 0
        if row['if_pred']  == -1: s += 25
        if row['lof_pred'] == -1: s += 25
        if row['alerts_total'] > 2: s += 25
        if row['actions_total'] > 20: s += 25
        return s

    agg_df['risk_score'] = agg_df.apply(calc_risk, axis=1)
    agg_df['status']     = agg_df['risk_score'].apply(lambda x: 'ALERT' if x > 50 else 'NORMAL')
    agg_df['IF Model']   = agg_df['if_pred'].map({1:'Normal', -1:'Anomaly'})
    agg_df['LOF Model']  = agg_df['lof_pred'].map({1:'Normal', -1:'Anomaly'})
    agg_df['Last Seen']  = agg_df['last_seen'].dt.strftime('%d %b %Y %H:%M')

    total_users   = len(agg_df)
    normal_count  = sum(agg_df['status'] == 'NORMAL')
    alert_count   = sum(agg_df['status'] == 'ALERT')
    total_events  = len(logs_df)
    alert_events  = sum(logs_df['status'] == 'ALERT')
else:
    agg_df = pd.DataFrame(columns=[
        'user','actions_total','alerts_total','if_pred','lof_pred',
        'risk_score','status','IF Model','LOF Model','Last Seen'
    ])
    total_users = normal_count = alert_count = total_events = alert_events = 0

# --- Metrics ---
m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Users",   total_users)
m2.metric("Normal Users",  normal_count)
m3.metric("Alert Users",   alert_count,  delta=f"{alert_count} need attention" if alert_count else None, delta_color="inverse")
m4.metric("Total Events",  total_events)

st.markdown("<br>", unsafe_allow_html=True)

# --- Charts ---
st.markdown("<div class='section-rule'>Overview</div>", unsafe_allow_html=True)
chart_col1, chart_col2, chart_col3 = st.columns([1, 1, 2])

with chart_col1:
    st.markdown("**Risk distribution**")
    if total_users > 0:
        fig, ax = plt.subplots(figsize=(3.5, 3))
        ax.pie([normal_count, alert_count],
               labels=['Normal','Alert'],
               autopct='%1.0f%%',
               colors=['#3B6D11','#A32D2D'],
               startangle=90,
               wedgeprops=dict(width=0.55))
        for t in ax.texts: t.set_fontsize(10)
        fig.patch.set_alpha(0)
        ax.set_facecolor('none')
        st.pyplot(fig)
    else:
        st.info("No data yet")

with chart_col2:
    st.markdown("**Event types**")
    if not logs_df.empty:
        action_counts = {}
        for a in logs_df['action']:
            if 'login_success' in str(a):   k = 'Login success'
            elif 'login_attempt' in str(a): k = 'Failed login'
            elif 'logout' in str(a):        k = 'Logout'
            elif 'accessed' in str(a):      k = 'File access'
            else:                           k = 'Other'
            action_counts[k] = action_counts.get(k, 0) + 1

        fig2, ax2 = plt.subplots(figsize=(3.5, 3))
        ax2.pie(list(action_counts.values()),
                labels=list(action_counts.keys()),
                autopct='%1.0f%%',
                colors=['#1D9E75','#A32D2D','#5F5E5A','#185FA5','#854F0B'],
                startangle=90,
                wedgeprops=dict(width=0.55))
        for t in ax2.texts: t.set_fontsize(9)
        fig2.patch.set_alpha(0)
        ax2.set_facecolor('none')
        st.pyplot(fig2)
    else:
        st.info("No data yet")

with chart_col3:
    st.markdown("**Weekly activity**")
    if not logs_df.empty:
        daily = logs_df.groupby(['date_str','status']).size().unstack(fill_value=0).reset_index()
        if 'ALERT'  not in daily.columns: daily['ALERT']  = 0
        if 'NORMAL' not in daily.columns: daily['NORMAL'] = 0
        fig3, ax3 = plt.subplots(figsize=(6, 3))
        x = range(len(daily))
        ax3.bar(x, daily['NORMAL'], label='Normal', color='#3B6D11', alpha=0.9)
        ax3.bar(x, daily['ALERT'],  label='Alert',  color='#A32D2D', alpha=0.9,
                bottom=daily['NORMAL'])
        ax3.set_xticks(list(x))
        ax3.set_xticklabels(daily['date_str'], fontsize=9)
        ax3.legend(fontsize=9)
        ax3.spines['top'].set_visible(False)
        ax3.spines['right'].set_visible(False)
        ax3.set_facecolor('none')
        fig3.patch.set_alpha(0)
        st.pyplot(fig3)
    else:
        st.info("No data yet")

# --- Risk Table ---
st.markdown("<div class='section-rule'>User risk table</div>", unsafe_allow_html=True)

if not agg_df.empty:
    display_df = agg_df[[
        'user','risk_score','IF Model','LOF Model',
        'alerts_total','actions_total','Last Seen','status'
    ]].sort_values('risk_score', ascending=False).copy()
    display_df.columns = [
        'User','Risk Score','IF Model','LOF Model',
        'Alert Events','Total Actions','Last Seen','Status'
    ]

    def highlight_risk(row):
        if row['Status'] == 'ALERT':
            return ['background-color:#fff0f0;color:#7a1f1f'] * len(row)
        return [''] * len(row)

    st.dataframe(
        display_df.style.apply(highlight_risk, axis=1),
        use_container_width=True,
        hide_index=True
    )

    # --- Email alert button ---
    st.markdown("<div class='section-rule'>Actions</div>", unsafe_allow_html=True)
    alert_users = agg_df[agg_df['status'] == 'ALERT']['user'].tolist()
    if alert_users:
        col_btn1, col_btn2, _ = st.columns([2, 2, 4])
        with col_btn1:
            if st.button(f"📧 Send alert email ({len(alert_users)} users)"):
                for u in alert_users:
                    row = agg_df[agg_df['user'] == u].iloc[0]
                    send_alert(
                        user=u,
                        reason="High risk score detected on dashboard",
                        details=f"Risk score: {row['risk_score']} | Alerts: {row['alerts_total']} | IF: {row['IF Model']} | LOF: {row['LOF Model']}"
                    )
                st.success(f"Alert emails sent for: {', '.join(alert_users)}")
else:
    st.info("No user data yet")

# --- Event Log with filters ---
st.markdown("<div class='section-rule'>Event log</div>", unsafe_allow_html=True)

if not logs_df.empty:
    f1, f2, f3, f4, f5 = st.columns([2, 1.5, 1, 1, 1])

    with f1:
        search = st.text_input("", placeholder="Search user or file...",
                               label_visibility="collapsed")
    with f2:
        status_filter = st.selectbox("", ["All statuses","ALERT","NORMAL"],
                                     label_visibility="collapsed")
    with f3:
        time_from = st.time_input("From", value=None, label_visibility="visible")
    with f4:
        time_to = st.time_input("To", value=None, label_visibility="visible")
    with f5:
        st.markdown("<br>", unsafe_allow_html=True)
        download_clicked = st.button("⬇ Download CSV")

    filtered = logs_df.copy().sort_values('timestamp', ascending=False)

    if search:
        filtered = filtered[
            filtered['user'].str.contains(search, case=False, na=False) |
            filtered['action'].str.contains(search, case=False, na=False)
        ]
    if status_filter != "All statuses":
        filtered = filtered[filtered['status'] == status_filter]
    if time_from:
        filtered = filtered[filtered['timestamp'].dt.time >= time_from]
    if time_to:
        filtered = filtered[filtered['timestamp'].dt.time <= time_to]

    st.markdown(f"<p style='font-size:11px;color:grey;'>{len(filtered)} event(s) found</p>",
                unsafe_allow_html=True)

    if download_clicked:
        csv_buf = io.StringIO()
        filtered[['timestamp','user','action','status']].to_csv(csv_buf, index=False)
        st.download_button(
            label="📥 Click to download",
            data=csv_buf.getvalue(),
            file_name=f"logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

    def highlight_logs(row):
        if row['status'] == 'ALERT':
            return ['background-color:#fff0f0;color:#7a1f1f'] * len(row)
        return ['background-color:#f0fff4;color:#1a4a0a'] * len(row)

    st.dataframe(
        filtered[['timestamp','user','action','status']].style.apply(highlight_logs, axis=1),
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No logs yet")

# --- Footer ---
st.markdown("<hr style='border:none;border-top:1px solid rgba(128,128,128,0.2);margin-top:2rem;'>",
            unsafe_allow_html=True)
st.markdown("""
    <div style='display:flex;justify-content:space-between;
    font-size:11px;color:grey;letter-spacing:0.06em;padding-bottom:1rem;'>
        <span>User Behaviour Monitor — Thesis Project</span>
        <span>Raspberry Pi SOC System</span>
    </div>
""", unsafe_allow_html=True)