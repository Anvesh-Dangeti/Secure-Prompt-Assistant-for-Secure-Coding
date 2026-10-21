# flask_vuln_app behaviour tests

Run by verification gate 3b (lab mode) against a *patched scratch copy* of
`fixtures/flask_vuln_app`, with the interpreter from
`scripts/install_fixture_env.py`:

```
.tools/fixture/Scripts/python -P -m pytest -c fixtures/flask_vuln_app_tests/pytest.ini \
    --rootdir fixtures/flask_vuln_app_tests fixtures/flask_vuln_app_tests   # PYTHONPATH=fixtures/flask_vuln_app
```

Rules these tests follow:

- **Behaviour, not implementation.** Each test checks what a seeded function does
  for valid input, so it passes on the vulnerable original *and* on any correct
  fix. Whether the weakness is gone is the scanners' job (gates 1 and 2), not
  these tests'.
- **Nothing leaves the process.** Every process-spawning entry point
  (`subprocess.*`, `os.system`, `os.popen`) is replaced by a recorder, and the
  database is a temporary SQLite file.
- **They live outside the fixture.** Inside it, the scanners would report the
  tests' own `assert`s and change the fixture's asserted baseline.

Known limits, stated rather than hidden:

- `restore_session` (CWE-502) is checked for presence only. A correct fix changes
  the wire format (pickle to JSON), and no single input is valid for both.
- The tests run with the deployment configuration the fixture's own settings imply:
  `API_TOKEN` is set in the environment (`conftest.py`), so the standard CWE-798 fix
  (`API_TOKEN = os.environ["API_TOKEN"]` or `os.getenv("API_TOKEN")`) keeps its
  behaviour. A fix that invents a *different* variable name (for example
  `PAYMENT_API_TOKEN`) still fails: the application then needs new configuration
  that nothing provides.
