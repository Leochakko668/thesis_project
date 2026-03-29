import subprocess
import time
from collections import defaultdict

# Start journalctl process to follow SSH logs in real-time
proc = subprocess.Popen(
    ["journalctl", "-f", "-u", "ssh.service"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# Store user behaviour profiles
user_profiles = defaultdict(lambda: {
    "login_hours": [],
    "failed_attempts": 0,
    "last_ip": None
})

def update_profile(user, login_hour, ip):
    """Update behaviour profile for user"""

    profile = user_profiles[user]
    profile["login_hours"].append(login_hour)
    profile["last_ip"] = ip

    check_behaviour(user, login_hour)

def check_behaviour(user, login_hour):
    """Classify behaviour patterns"""

    profile = user_profiles[user]

    # OFF-HOUR LOGIN
    if login_hour < 6 or login_hour > 22:
        print(f"[ALERT] Off-hour login detected for {user} at {login_hour}:00")

    # TOO MANY FAILED LOGINS
    if profile["failed_attempts"] > 5:
        print(f"[ALERT] Multiple failed login attempts for {user}")

def parse_journal_line(line):
    """Extract behaviour signals from logs"""

    # SUCCESSFUL LOGIN
    if "Accepted password for" in line:
        parts = line.strip().split()

        user = parts[8]

        ip = parts[10] if len(parts) > 10 else "unknown"

        login_hour = int(time.strftime("%H"))

        return user, login_hour, ip, "success"

    # FAILED LOGIN
    if "Failed password for" in line:

        parts = line.strip().split()

        try:
            user = parts[8]
        except:
            user = "unknown"

        ip = parts[-4] if len(parts) > 10 else "unknown"

        return user, None, ip, "fail"

    return None, None, None, None


print("Real-time SSH Behaviour Monitoring Started...")

while True:

    line = proc.stdout.readline()

    if line:

        user, login_hour, ip, event = parse_journal_line(line)

        if event == "success":

            update_profile(user, login_hour, ip)

            print(f"[INFO] Login success | user={user} ip={ip} hour={login_hour}")

        elif event == "fail":

            user_profiles[user]["failed_attempts"] += 1

            print(f"[WARNING] Failed login attempt | user={user} ip={ip}")

    else:
        time.sleep(0.5)
