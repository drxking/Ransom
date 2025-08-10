#!/usr/bin/env python3
# Benign C2 demo server (localhost only)
from flask import Flask, request, jsonify
from datetime import datetime
import threading

app = Flask(__name__)

# Simple in-memory state
bots = {}         # bot_id -> {"last_seen": ts, "tasks": [ ... ]}
global_tasks = [] # tasks all bots can pull once

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    bot_id = data.get("bot_id")
    if not bot_id:
        return jsonify({"error": "missing bot_id"}), 400
    if bot_id not in bots:
        bots[bot_id] = {"last_seen": now_iso(), "tasks": []}
    return jsonify({"status": "ok", "server_time": now_iso()})

@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    data = request.get_json(silent=True) or {}
    bot_id = data.get("bot_id")
    info = data.get("info", {})
    if not bot_id or bot_id not in bots:
        return jsonify({"error": "unregistered"}), 400
    bots[bot_id]["last_seen"] = now_iso()
    # Return any queued tasks for this bot; also drain global tasks (one-time)
    tasks = []
    # per-bot tasks
    while bots[bot_id]["tasks"]:
        tasks.append(bots[bot_id]["tasks"].pop(0))
    # global tasks: give one per heartbeat for demo
    if global_tasks:
        tasks.append(global_tasks.pop(0))
    return jsonify({"status": "ok", "tasks": tasks, "server_time": now_iso(), "echo_info": info})

@app.route("/report", methods=["POST"])
def report():
    data = request.get_json(silent=True) or {}
    bot_id = data.get("bot_id")
    result = data.get("result")
    if not bot_id or bot_id not in bots:
        return jsonify({"error": "unregistered"}), 400
    print(f"[REPORT] {bot_id}: {result}")
    return jsonify({"status": "received"})

@app.route("/admin/queue", methods=["POST"])
def admin_queue():
    """
    Add a benign task.
    Example JSON:
    { "scope": "global", "task": {"action": "print", "args": "hello from server"} }
    or
    { "scope": "bot", "bot_id": "bot-123", "task": {...} }
    """
    data = request.get_json(silent=True) or {}
    task = data.get("task")
    scope = data.get("scope", "global")
    if not task:
        return jsonify({"error": "missing task"}), 400
    if scope == "bot":
        bot_id = data.get("bot_id")
        if not bot_id or bot_id not in bots:
            return jsonify({"error": "unknown bot_id"}), 400
        bots[bot_id]["tasks"].append(task)
    else:
        global_tasks.append(task)
    return jsonify({"status": "queued"})

@app.route("/admin/status", methods=["GET"])
def status():
    return jsonify({"bots": bots, "global_queue_len": len(global_tasks), "server_time": now_iso()})

if __name__ == "__main__":
    # Bind to loopback only; debug off for clarity
    app.run(host="127.0.0.1", port=8080, debug=False)
