"""A01:2021 — Broken Access Control lab. FOR AUTHORIZED TESTING ONLY."""
from flask import Flask, jsonify, request, Response

app = Flask(__name__)

USERS = {
    1: {"id": 1, "name": "alice", "email": "alice@corp.com", "role": "admin", "salary": 95000},
    2: {"id": 2, "name": "bob",   "email": "bob@corp.com",   "role": "user",  "salary": 62000},
    3: {"id": 3, "name": "carol", "email": "carol@corp.com", "role": "user",  "salary": 58000},
}

@app.route("/health")
def health():
    return "ok", 200

# VULNERABLE: no auth check — any user can fetch any profile (IDOR)
@app.route("/api/users/<int:uid>")
def get_user(uid):
    user = USERS.get(uid)
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)

# VULNERABLE: admin panel accessible without authentication
@app.route("/admin")
def admin():
    return jsonify({"panel": "admin", "users": list(USERS.values())}), 200

@app.route("/admin/")
def admin_slash():
    return admin()

# Clean control: requires header X-Auth: admin
@app.route("/api/users/<int:uid>/secure")
def get_user_secure(uid):
    if request.headers.get("X-Auth") != "admin":
        return Response("Forbidden", status=403)
    user = USERS.get(uid)
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
