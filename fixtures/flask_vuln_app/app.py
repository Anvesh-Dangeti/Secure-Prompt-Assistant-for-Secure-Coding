"""
DELIBERATELY VULNERABLE CODE -- TEST FIXTURE ONLY.

This application exists to give the scanners something to find. It is isolated
under fixtures/, never imported by the Secure Prompt Assistant, and must never
be deployed or copied from.

Each scoped CWE is seeded exactly once, inside its own named function, so
fixtures/flask_vuln_app/ground_truth.yaml can locate every weakness by symbol
rather than by line number (line numbers drift whenever this file is edited).
"""

import os
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, request

from config import API_TOKEN
from crypto_utils import hash_password, make_reset_token

app = Flask(__name__)
DATA_DIR = "/srv/app/data"


def load_settings(path):
    """Safe use of PyYAML -- the A06 weakness is the pinned *version*, not this call."""
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@app.route("/user")
def get_user():
    """CWE-89 SQL injection: request data formatted straight into the query."""
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT name, email FROM users WHERE id = '%s'" % user_id)
    return {"rows": cursor.fetchall()}


@app.route("/ping")
def ping_host():
    """CWE-78 OS command injection: request data reaches a shell."""
    host = request.args.get("host")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/greet")
def greet():
    """CWE-79 cross-site scripting: request data returned as HTML unescaped."""
    name = request.args.get("name", "")
    return "<h1>Hello, %s!</h1>" % name


@app.route("/files")
def download_file():
    """CWE-22 path traversal: request data joined into a filesystem path."""
    filename = request.args.get("name")
    with open(os.path.join(DATA_DIR, filename), encoding="utf-8") as handle:
        return handle.read()


@app.route("/session", methods=["POST"])
def restore_session():
    """CWE-502 deserialisation of untrusted data."""
    blob = request.get_data()
    return {"session": str(pickle.loads(blob))}


@app.route("/register", methods=["POST"])
def register():
    """Uses the weak helpers seeded in crypto_utils.py (CWE-327, CWE-330)."""
    password_hash = hash_password(request.form["password"])
    return {"hash": password_hash, "reset_token": make_reset_token(), "api": bool(API_TOKEN)}


if __name__ == "__main__":
    # CWE-94 / CWE-215: Flask debug mode exposes the interactive Werkzeug console.
    app.run(debug=True)
