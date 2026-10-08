"""
DELIBERATELY VULNERABLE CODE — DEMO FIXTURE ONLY.

This file exists to give the scanners something to find. It is an isolated test
fixture and is NEVER imported by the application. Do not copy anything from here.

Each function below seeds exactly one of the project's scoped CWEs so that the
detection results can be checked against `ground_truth.yaml`.

Scoped CWEs seeded here (see docs/scope_decisions.md):
    CWE-89   SQL Injection                    OWASP A03
    CWE-78   OS Command Injection             OWASP A03
    CWE-798  Hard-coded Credentials           OWASP A07
    CWE-22   Path Traversal                   OWASP A01
    CWE-327  Weak Cryptography                OWASP A02
    CWE-330  Insufficiently Random Values     OWASP A02
    CWE-502  Unsafe Deserialization           OWASP A08
    CWE-94   Flask debug mode                 OWASP A05
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

# CWE-798 — hard-coded credentials. Detected by BOTH Bandit and Gitleaks,
# which makes this our cross-scanner corroboration case.
DB_PASSWORD = "SuperSecret123!"
API_TOKEN = "sk_live_51H8xQ2eZvKYlo2C0aBcDeFgHiJkLmNoP"


@app.route("/user")
def get_user():
    """CWE-89 — SQL injection via string-formatted query."""
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Vulnerable: user input concatenated straight into SQL.
    cursor.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
    return str(cursor.fetchall())


@app.route("/ping")
def ping_host():
    """CWE-78 — OS command injection.

    Paper 3 found this was the most frequent weakness in LLM-generated Python
    AND that no prompting technique reduced it. It is our hardest target.
    """
    host = request.args.get("host")
    # Vulnerable: shell=True with attacker-controlled input.
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/read")
def read_file():
    """CWE-22 — path traversal."""
    filename = request.args.get("name")
    # Vulnerable: no normalisation, no containment check.
    with open(os.path.join("/var/data", filename)) as handle:
        return handle.read()


def hash_password(password):
    """CWE-327 — weak/broken cryptographic hash."""
    # Vulnerable: MD5 is unsuitable for password hashing.
    return hashlib.md5(password.encode()).hexdigest()


def generate_session_token():
    """CWE-330 — insufficiently random values.

    Paper 3 observed models correctly switching to `secrets` under RCI prompting.
    """
    # Vulnerable: `random` is not cryptographically secure.
    return str(random.randint(100000, 999999))


@app.route("/load", methods=["POST"])
def load_session():
    """CWE-502 — deserialization of untrusted data."""
    blob = request.get_data()
    # Vulnerable: pickle executes arbitrary code during load.
    return str(pickle.loads(blob))


if __name__ == "__main__":
    # CWE-94 / CWE-215 — Flask debug mode enables the Werkzeug console.
    # Paper 3: baseline prompts produced 54 instances on GPT-4; RCI reduced it to 3.
    app.run(debug=True, host="0.0.0.0")
