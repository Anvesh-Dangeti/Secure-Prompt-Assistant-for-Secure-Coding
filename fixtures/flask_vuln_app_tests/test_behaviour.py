"""One behaviour test per seeded function of flask_vuln_app (see README.md for the rules)."""

from __future__ import annotations

import importlib
import sqlite3

import flask


def test_get_user_returns_the_row(client, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with sqlite3.connect("app.db") as db:
        db.execute("CREATE TABLE users (id TEXT, name TEXT, email TEXT)")
        db.execute("INSERT INTO users VALUES ('1', 'ann', 'ann@example.com')")
        db.execute("INSERT INTO users VALUES ('2', 'bob', 'bob@example.com')")
    response = client.get("/user?id=1")
    assert response.status_code == 200
    assert "ann@example.com" in response.get_data(as_text=True)
    assert "bob@example.com" not in response.get_data(as_text=True)


def test_ping_host_passes_the_host_to_ping(client, commands):
    response = client.get("/ping?host=127.0.0.1")
    assert response.status_code == 200
    assert "1 received" in response.get_data(as_text=True)
    assert any("127.0.0.1" in str(args) for args, _ in commands)
    assert any("ping" in str(args) for args, _ in commands)


def test_greet_contains_the_name(client):
    response = client.get("/greet?name=Ann")
    assert response.status_code == 200
    assert "Hello" in response.get_data(as_text=True) and "Ann" in response.get_data(as_text=True)


def test_download_file_returns_the_file(client, module, tmp_path, monkeypatch):
    (tmp_path / "report.txt").write_text("quarterly numbers", encoding="utf-8")
    monkeypatch.setattr(module, "DATA_DIR", str(tmp_path))
    response = client.get("/files?name=report.txt")
    assert response.status_code == 200
    assert "quarterly numbers" in response.get_data(as_text=True)


def test_restore_session_route_still_exists(module):
    rules = {rule.rule: rule.methods for rule in module.app.url_map.iter_rules()}
    assert "/session" in rules and "POST" in rules["/session"]


def test_register_returns_a_hash_and_a_token(client):
    response = client.post("/register", data={"password": "correct horse"})
    assert response.status_code == 200
    body = response.get_json()
    assert body["hash"] and body["hash"] != "correct horse"
    assert isinstance(body["reset_token"], str) and body["reset_token"]
    assert "api" in body


def test_crypto_helpers():
    import crypto_utils

    hashed = crypto_utils.hash_password("pw")
    assert hashed and hashed != "pw"
    token = crypto_utils.make_reset_token()
    assert isinstance(token, str) and len(token) >= 6


def test_config_still_provides_the_token_setting():
    import config

    assert isinstance(config.API_TOKEN, str)


def test_load_settings_reads_yaml(module, tmp_path):
    path = tmp_path / "settings.yaml"
    path.write_text("debug: false\nworkers: 2\n", encoding="utf-8")
    assert module.load_settings(str(path)) == {"debug": False, "workers": 2}


def test_importing_the_app_does_not_start_a_server(module, monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("app.run() called at import time")

    monkeypatch.setattr(flask.Flask, "run", refuse)
    importlib.reload(module)
