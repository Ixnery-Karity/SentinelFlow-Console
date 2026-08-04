"""Flask API and static UI for the Security Workflow Console."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from core import audit_code, timestamp
from workflow import run_workflow

ROOT = Path(__file__).resolve().parent
app = Flask(__name__, static_folder=str(ROOT / "static"), static_url_path="/static")


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "security-workflow-console", "time": timestamp()})


@app.post("/api/workflow/run")
def workflow_run():
    payload = request.get_json(silent=True) or {}
    return jsonify(run_workflow(payload))


@app.post("/api/audit")
def audit():
    payload = request.get_json(silent=True) or {}
    return jsonify(audit_code(str(payload.get("code") or "")))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(__import__("os").getenv("PORT", "5000")), debug=False)

