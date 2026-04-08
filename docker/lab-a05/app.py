"""A05:2021 — Security Misconfiguration lab. FOR AUTHORIZED TESTING ONLY."""
import os, sys
from flask import Flask, jsonify, Response

app = Flask(__name__)

@app.route("/health")
def health():
    return "ok", 200

# VULNERABLE: no security headers at all
@app.route("/")
def index():
    return Response("<html><body><h1>Lab A05</h1></body></html>", mimetype="text/html")

# VULNERABLE: debug/actuator-style endpoints exposed in production
@app.route("/actuator/env")
def actuator_env():
    return jsonify({
        "activeProfiles": ["prod"],
        "DATABASE_URL": "postgres://admin:s3cr3t@db:5432/app",
        "SECRET_KEY": "hardcoded-secret-key-12345",
        "python": sys.version,
    })

@app.route("/actuator/beans")
def actuator_beans():
    return jsonify({"beans": ["UserService", "AuthService", "DatabasePool"]})

@app.route("/server-status")
def server_status():
    return jsonify({"status": "ok", "version": "Flask/3.0.3 Python/3.11"})

# VULNERABLE: verbose stack trace on error
@app.route("/crash")
def crash():
    raise RuntimeError("Traceback (most recent call last): File app.py line 42 in crash")

@app.errorhandler(500)
def handle_500(e):
    return Response(f"Internal Server Error\n{e}", status=500, mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, debug=False)
