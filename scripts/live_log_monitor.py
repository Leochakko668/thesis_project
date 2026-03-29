import subprocess

print("Monitoring security logs...\n")

process = subprocess.Popen(
    ["journalctl", "-f"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

for line in process.stdout:
    print(line.strip())
