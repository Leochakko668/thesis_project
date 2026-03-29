import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

SENDER_EMAIL = "your_gmail@gmail.com"
SENDER_PASSWORD = "your_app_password"
RECEIVER_EMAIL = "it_person@institution.com"

def send_alert(user, reason, details=""):
    try:
        msg = MIMEMultipart()
        msg['Subject'] = f"SECURITY ALERT - Suspicious activity by '{user}'"
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        body = f"""
        SECURITY ALERT
        Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        User     : {user}
        Reason   : {reason}
        Details  : {details}
        Please check your dashboard immediately.
        """
        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        print(f"Alert email sent for user '{user}'")
    except Exception as e:
        print(f"Failed to send email: {e}")