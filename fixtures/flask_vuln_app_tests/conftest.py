"""Shared fixtures: the Flask test client, and a recorder in place of every way to start a process."""

from __future__ import annotations

import io
import os
import subprocess

import pytest

OUTPUT = "PING 127.0.0.1: 1 packets transmitted, 1 received"

# Deployment configuration. The standard fix for the hard-coded credential (CWE-798)
# reads API_TOKEN from the environment, and a deployed app would have it set, so the
# behaviour tests run with it set too. The unmodified fixture ignores it and still passes.
# Set before any test imports the code under test (config is read at import time).
os.environ["API_TOKEN"] = "behaviour-test-token"


@pytest.fixture
def module():
    import app as fixture_app   # the code under test, from PYTHONPATH

    fixture_app.app.config["TESTING"] = True
    return fixture_app


@pytest.fixture
def client(module):
    return module.app.test_client()


@pytest.fixture
def commands(monkeypatch):
    """Record every attempted command instead of running it. Returns the list of calls."""
    calls: list[tuple] = []

    def out(kwargs):
        text = kwargs.get("text") or kwargs.get("universal_newlines") or kwargs.get("encoding")
        return OUTPUT if text else OUTPUT.encode()

    def run(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args[0] if args else kwargs.get("args"), 0, out(kwargs), out(kwargs)[:0])

    def check_output(*args, **kwargs):
        calls.append((args, kwargs))
        return out(kwargs)

    def call(*args, **kwargs):
        calls.append((args, kwargs))
        return 0

    class Popen:
        def __init__(self, *args, **kwargs):
            calls.append((args, kwargs))
            self.args, self.returncode, self._out = (args[0] if args else None), 0, out(kwargs)
            self.stdout = io.BytesIO(self._out) if isinstance(self._out, bytes) else io.StringIO(self._out)

        def communicate(self, *a, **k):
            return self._out, self._out[:0]

        def wait(self, *a, **k):
            return 0

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def system(command):
        calls.append(((command,), {}))
        return 0

    def popen(command, *a, **k):
        calls.append(((command,), {}))
        return io.StringIO(OUTPUT)

    for name, fake in {"run": run, "check_output": check_output, "call": call, "check_call": call,
                       "Popen": Popen}.items():
        monkeypatch.setattr(subprocess, name, fake)
    monkeypatch.setattr(os, "system", system)
    monkeypatch.setattr(os, "popen", popen)
    return calls
