# flask_vuln_app — deliberately vulnerable fixture

**Do not run, deploy, or copy from this code.** It exists only so the scanners have known weaknesses
to find, and it is never imported by the application.

One instance of each of the project's 10 scoped CWEs is seeded, each inside its own named symbol so
that `ground_truth.yaml` can locate it without line numbers:

| CWE | Weakness | Where |
|---|---|---|
| CWE-89 | SQL injection | `app.py::get_user` |
| CWE-78 | OS command injection | `app.py::ping_host` |
| CWE-79 | Cross-site scripting | `app.py::greet` |
| CWE-798 | Hard-coded credential | `config.py::API_TOKEN` |
| CWE-22 | Path traversal | `app.py::download_file` |
| CWE-327 | Broken hash (MD5) | `crypto_utils.py::hash_password` |
| CWE-330 | Insufficient randomness | `crypto_utils.py::make_reset_token` |
| CWE-502 | Unsafe deserialisation | `app.py::restore_session` |
| CWE-94 | Flask debug mode | `app.py::__main__` |
| CWE-1395 | Vulnerable dependency | `requirements.txt::PyYAML==5.3` |

The credential in `config.py` is fabricated and has never been valid.
