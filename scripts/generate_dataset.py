import pandas as pd
import random

rows = 50000

users = [
    "alice","bob","charlie","david","emma",
    "frank","grace","henry","irene","jack",
    "kevin","linda","mike","nina","oscar",
    "paul","queen","robert","sarah","tom"
]

data = []

for i in range(rows):

    user = random.choice(users)

    # user behaviour patterns
    if user in ["alice","emma","grace","linda","sarah"]:
        login_hour = random.randint(8,11)

    elif user in ["bob","henry","jack","mike"]:
        login_hour = random.randint(21,23)

    elif user in ["charlie","david","frank"]:
        login_hour = random.randint(12,16)

    else:
        login_hour = random.randint(6,22)

    files_accessed = random.randint(1,15)
    commands_executed = random.randint(5,30)
    session_duration = random.randint(10,120)
    failed_logins = random.randint(0,1)

    # rare anomaly injection
    if random.random() < 0.02:
        files_accessed = random.randint(40,120)
        commands_executed = random.randint(80,200)
        failed_logins = random.randint(3,8)

    data.append([
        user,
        login_hour,
        files_accessed,
        commands_executed,
        session_duration,
        failed_logins
    ])

df = pd.DataFrame(data, columns=[
    "user",
    "login_hour",
    "files_accessed",
    "commands_executed",
    "session_duration",
    "failed_logins"
])

df.to_csv("../data/user_activity.csv", index=False)

print("Dataset generated successfully (50000 rows)")
