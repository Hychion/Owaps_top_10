"""A07:2021 — Authentication Failures lab. FOR AUTHORIZED TESTING ONLY."""
from flask import Flask, jsonify, request, make_response

app = Flask(__name__)

# VULNERABLE: default credentials, no lockout
USERS = {
    "admin": "admin", "user": "password", "test": "test",
    "guest": "guest", "root": "root",
}

@app.route("/health")
def health():
    return "ok", 200

# VULNERABLE: no rate limiting, verbose error differentiation
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if username not in USERS:
        return jsonify({"error": "Unknown user"}), 401       # reveals valid usernames
    if USERS[username] != password:
        return jsonify({"error": "Wrong password"}), 401    # confirms user exists

    resp = make_response(jsonify({"token": f"token-{username}", "role": "admin" if username == "admin" else "user"}))
    # VULNERABLE: session cookie without Secure/HttpOnly/SameSite
    resp.headers["Set-Cookie"] = f"session=token-{username}; Path=/"
    return resp

@app.route("/api/login", methods=["POST"])
def api_login():
    return login()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=False)
