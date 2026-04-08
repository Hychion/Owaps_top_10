"""A03:2021 — Injection lab (SQLi, XSS, SSTI). FOR AUTHORIZED TESTING ONLY."""
import sqlite3
from flask import Flask, request, Response
from jinja2 import Environment  # sandbox-less env for SSTI demo

app = Flask(__name__)
DB = "/app/lab.db"

@app.route("/health")
def health():
    return "ok", 200

# VULNERABLE SQLi: raw string concatenation
@app.route("/")
def index():
    q = request.args.get("id", "1")
    try:
        conn = sqlite3.connect(DB)
        rows = conn.execute(f"SELECT * FROM products WHERE id = '{q}'").fetchall()
        conn.close()
        body = "<br>".join(str(r) for r in rows) or "No results"
    except sqlite3.OperationalError as e:
        body = f"DB error: {e}"
    html = f"<html><body><p>{body}</p></body></html>"
    return Response(html, mimetype="text/html")

# VULNERABLE XSS: reflects q unescaped
@app.route("/search")
def search():
    q = request.args.get("q", "")
    html = f"<html><body><p>Results for: {q}</p></body></html>"
    return Response(html, mimetype="text/html")

# VULNERABLE SSTI: renders user input as a Jinja2 template
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    env = Environment()  # No sandboxing — intentionally vulnerable
    tmpl = env.from_string(f"Hello {name}!")
    return Response(f"<html><body>{tmpl.render()}</body></html>", mimetype="text/html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
