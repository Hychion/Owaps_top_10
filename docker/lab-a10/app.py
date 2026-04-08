"""A10:2021 — SSRF lab. FOR AUTHORIZED TESTING ONLY."""
import requests as req_lib
from flask import Flask, jsonify, request, Response

app = Flask(__name__)

@app.route("/health")
def health():
    return "ok", 200

# VULNERABLE: fetches any URL passed by the user and returns the response
@app.route("/")
def index():
    url = request.args.get("url", "")
    if not url:
        return Response("<html><body><h1>Lab A10 — SSRF</h1><p>Use ?url=http://...</p></body></html>",
                        mimetype="text/html")
    try:
        resp = req_lib.get(url, timeout=3, allow_redirects=True)
        # VULNERABLE: returns raw content including internal metadata
        return Response(resp.text, status=resp.status_code, mimetype="text/plain")
    except req_lib.exceptions.ConnectionError as e:
        return Response(f"Connection error: {e}", status=502, mimetype="text/plain")
    except req_lib.exceptions.Timeout:
        return Response("Request timed out", status=504, mimetype="text/plain")

# Same vulnerability via other parameter names
@app.route("/fetch")
def fetch():
    url = request.args.get("uri") or request.args.get("href") or request.args.get("src", "")
    if not url:
        return jsonify({"error": "provide uri, href or src parameter"}), 400
    try:
        resp = req_lib.get(url, timeout=3)
        return Response(resp.text, status=resp.status_code, mimetype="text/plain")
    except Exception as e:
        return Response(str(e), status=502, mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5005, debug=False)
