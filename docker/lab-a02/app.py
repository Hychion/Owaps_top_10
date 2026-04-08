"""A02:2021 — Cryptographic Failures lab. FOR AUTHORIZED TESTING ONLY."""
from flask import Flask, make_response

app = Flask(__name__)

@app.route("/health")
def health():
    return "ok", 200

# VULNERABLE: HTTP only, no HSTS, cookie without Secure/HttpOnly/SameSite
@app.route("/")
def index():
    resp = make_response("<html><body><h1>Lab A02</h1></body></html>")
    # No Strict-Transport-Security header
    # No X-Content-Type-Options
    # No X-Frame-Options
    resp.headers["Set-Cookie"] = "session=abc123; Path=/"  # missing Secure/HttpOnly/SameSite
    return resp

# VULNERABLE: password visible in URL query string
@app.route("/login")
def login():
    return make_response("<html><body>Login</body></html>")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
