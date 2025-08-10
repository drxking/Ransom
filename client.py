#!/usr/bin/env python3
# Benign bot client (localhost only)
import time
import uuid
import requests
from datetime import datetime

SERVER = "http://127.0.0.1:8080"
BOT_ID = f"bot-{uuid.uuid4().hex[:8]}"

def register():
    r = requests.post(f"{SERVER}/register", json={"bot_id": BOT_ID})
    r.raise_for_status()
    print("[*] Registered:", r.json())

def heartbeat():
    payload = {
        "bot_id": BOT_ID,
        "info": {"time": datetime.utcnow().isoformat() + "Z", "note": "hello from benign bot"}
    }
    r = requests.post(f"{SERVER}/heartbeat", json=payload)
    r.raise_for_status()
    return r.json().get("tasks", [])

def execute(task):
    """
    Benign actions only, for demo:
      - action=print : print args
      - action=date  : print server-style timestamp
    """
    action = task.get("action")
    if action == "print":
        msg = task.get("args", "")
        result = f"PRINT >> {msg}"
    elif action == "date":
        result = f"DATE >> {datetime.utcnow().isoformat()}Z"
    else:
        result = f"UNKNOWN_ACTION >> {action}"
    print(result)
    # Report back to server
    requests.post(f"{SERVER}/report", json={"bot_id": BOT_ID, "result": result})

if __name__ == "__main__":
    print(f"[i] Starting benign client BOT_ID={BOT_ID}")
    register()
    try:
        while True:
            tasks = heartbeat()
            for t in tasks:
                execute(t)
            time.sleep(5)  # fixed interval; you can change to jittered sleeps for realism
    except KeyboardInterrupt:
        print("\n[i] Stopped.")
