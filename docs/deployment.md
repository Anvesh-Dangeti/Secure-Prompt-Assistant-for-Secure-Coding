# Using a shared server: connecting a project folder with `spa`

The tool was built to run on the developer's own machine: the web interface reads a checkout by its absolute path, and
one key (`SPA_API_KEY`) signs in. Neither carries over to a server that a team shares. The server cannot see a folder
on someone's laptop, and one shared key cannot tell developers apart or be taken back from one of them.

On a shared server, a developer uses a small command, **`spa`**, in their project folder. Snyk's CLI, SonarScanner and
Semgrep's CI command work the same way:

```
developer's laptop                                     shared server
───────────────────                                    ──────────────────────────────────────────────
project folder                                         TLS reverse proxy (Caddy / nginx), port 443
  spa connect / scan / prompt / verify  ── HTTPS ──►     └─► uvicorn app.main  (127.0.0.1:8000, non-root user)
  token in the user's config dir                                ├─ Semgrep · Bandit · Gitleaks · pip-audit
  .spa/connection.json (no secret)                              ├─ SQLite (findings, history, token hashes)
                                                                └─ web interface (127.0.0.1:8080, admins via SSH tunnel)
```

- **The scanners, the prompt builder and the verification checks run on the server.** The laptop needs no scanner,
  no model and no Python packages beyond `spa` itself, which uses only the standard library.
- **The server stays the independent judge.** A developer's machine never reports results of its own; the server
  re-scans what it is sent. A modified client could send different code, but it could never send a verdict.
- **Every developer has their own token,** for one project, with an expiry, which can be revoked on its own.
  `SPA_API_KEY` stays with the administrator.

## What a developer does

```bash
pip install ./libs/spa-connect        # or the wheel the administrator hands out; installs the `spa` command
cd path/to/helpdesk-portal

spa connect --server https://spa.example.edu      # paste the token when asked (input hidden)
spa scan --label "before the fix"                 # pack -> upload -> four scanners -> findings
spa findings                                      # open findings with their IDs
spa prompt 5 > prompt.txt                         # a linted remediation prompt (S7 by default; --strategy S7m)
#   ... paste it into Copilot or another coding assistant, review its change ...
spa verify 5                                      # re-scan this folder; checks 1, 2, 3a; exit 0 = VERIFIED_RESOLVED
```

| Command | What it does |
|---|---|
| `spa connect --server URL [--project NAME] [--token-stdin]` | Checks the token with the server (`/api/v1/whoami`). It then saves the token in the user's config dir and writes `.spa/connection.json` |
| `spa status` | Shows which project and server this folder is connected to, and whether the token still works |
| `spa scan [--label TEXT]` | Packs the folder, uploads it and scans it on the server. It prints the scan's status and the lifecycle changes |
| `spa findings [--all \| --state STATE]` | Lists the project's tracked findings. Open ones (new, still open, regression) are shown by default |
| `spa prompt ID [--strategy S] [-o FILE]` | Sends the finding's one file and prints the remediation prompt. The lint result and token count go to stderr |
| `spa verify ID` | Scans again with the label `verify #ID` and judges the fix against that scan |
| `spa disconnect` | Forgets the token and removes the link |

`spa` finds the connection from any sub-folder, as git finds `.git`. Exit codes are 0 (done; for `verify`,
`VERIFIED_RESOLVED`), 1 (the scan or the fix did not pass) and 2 (a usage or connection problem), so the commands
also work in scripts.

**In CI**, store the token as a secret and pipe it in:
`echo "$SPA_TOKEN" | spa connect --server https://spa.example.edu --token-stdin && spa scan`.
If `SPA_TOKEN` is set, it is also used instead of the stored token.

## What leaves the developer's machine

| Command | Sent | Kept on the server |
|---|---|---|
| `connect`, `status` | the token, in the `Authorization` header only | the token's last-used time |
| `scan`, `verify` | the project folder, **minus** version-control data, virtual environments, dependency caches, local secret files (`.env`, `.env.*`; `.env.example` is kept), symbolic links and junctions, and anything listed in `.spaignore` | findings with redacted snippets, and structural facts about flagged functions. **The upload is deleted after the scan** |
| `prompt` | **one file**: the file the finding is in, and only if its path matches the finding exactly | nothing. The file is deleted when the request ends |
| `findings` | nothing | — |

A secret hard-coded **in source code** is still uploaded, because finding it is the point. Gitleaks's output is
masked, and every snippet is redacted before it is stored.

`.spaignore` takes one glob per line, `#` for comments. A plain name (`*.csv`) matches anywhere; a leading or inner
`/` (`/notes.txt`, `docs/build/*`) is anchored to the project root; a trailing `/` (`data/`) matches folders only.
The server's limits are checked before the upload, so a project that is too big fails at once with a hint: 50 MB
packed, 5,000 files, 20 MB per file, 24 levels deep.

## What the administrator does

1. **Install** the server as in the README's *Setup* section, as an unprivileged user. `SPA_ALLOW_ELEVATED` stays
   off, so the scanners refuse to run as root.
2. **Configure** `.env`: set `SPA_API_KEY` (the administrator's key), `SPA_DATABASE_URL`, the scanner paths if they
   are not on `PATH`, and keep `SPA_LLM_PROVIDER=template`. Developer mode needs no model.
3. **Run the API on loopback** with `uvicorn app.main:app --host 127.0.0.1 --port 8000`, under a service manager
   such as systemd.
4. **Put a TLS reverse proxy in front.** It needs a public certificate, a request-body limit of about 51 MB (the
   upload cap plus framing) and a read timeout of at least 15 minutes, because scans run synchronously. With Caddy:
   ```
   spa.example.edu {
       request_body { max_size 51MB }
       reverse_proxy 127.0.0.1:8000 { transport http { read_timeout 15m } }
   }
   ```
5. **Issue tokens**, one per developer and project. The token is printed once; hand it over privately.
   ```bash
   python -m app.cli token create --project helpdesk-portal --name rahul-laptop [--days 90]
   python -m app.cli token list            # prefix, owner, project, state, last use; never the token
   python -m app.cli token revoke 3        # takes effect on the next request
   ```
6. **The web interface stays local.** It still serves loopback only, with its own sign-in. An administrator reaches it
   through an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 server`, then `http://127.0.0.1:8080`). Developers use `spa`.

## Security controls

| Concern | Control | Tests |
|---|---|---|
| A stolen token | Stored only as a SHA-256 hash (the token is 256 random bits, so nothing can be guessed offline). It reaches one project, expires (90 days by default, 365 at most) and can be revoked. Junk is refused before any database lookup | `tests/unit/test_access_tokens.py` |
| Reading another project | Every route checks the project. Another project's data answers **404**, like data that does not exist, so a token cannot learn which projects the server holds. Creating projects and reading system information need the administrator key | `tests/security/test_token_authorization.py` |
| Two credentials in one request | A bearer token wins over an administrator key sent with it, so a request gets the narrowest access it carries | `test_token_authorization.py` |
| A token on the command line | `spa` has no `--token` option. The token comes from a hidden prompt or standard input, so it is not kept in shell history or shown in the process list | `libs/spa-connect/tests/test_connect_transport_cli.py` |
| A token committed with the code | It lives in the user's config dir (mode 0600 on POSIX), never in the project. The link file holds no secret. The `spa_pat_` prefix makes a leaked token easy to recognise | `test_connect_urls_config.py`, `tests/integration/test_spa_connect_e2e.py` |
| Interception | `spa` accepts `https://` only, with certificate verification and TLS 1.2 or later. `http://` is allowed only to this machine (127.0.0.1). No credentials, query string or fragment in the address. `SPA_CA_FILE` supports an in-house authority | `test_connect_urls_config.py` |
| A redirect that carries the token elsewhere | `spa` never follows a redirect; it reports it | `test_connect_transport_cli.py` |
| A link in the project pulling in outside files | Symbolic links and junctions are skipped, never followed. A file path sent by the server must stay inside the project folder, and a symlink there is refused | `test_connect_pack.py`, `test_connect_transport_cli.py` |
| The prompt route writing elsewhere | The path must equal the finding's own path. The file is written with a containment check into a private scratch directory, at most 1 MB, and deleted at the end of the request | `tests/integration/test_api_prompt.py` |
| A malicious upload | It goes through the same archive checks as every ZIP: traversal, links, bombs, counts and sizes | `tests/security/test_zip_extraction.py` |
| The token in logs or answers | Never logged or returned. `whoami` returns the name, project and expiry only | `test_token_authorization.py` |

## Limits, stated

- **Authorization is per-project tokens plus one administrator key.** There is no single sign-on, no roles within a
  project and no audit log beyond the token's last use and the scan history.
- **One node, SQLite, synchronous scans.** This suits a team with a handful of developers. A larger deployment would
  need a job queue for scans and a server database, and the code would not otherwise change: the ORM issues
  parameterised SQL either way.
- **Upload means trust in the server.** The code is sent to the server for the length of a scan. Teams that cannot
  allow that should run the tool locally, as before; both ways remain supported.
- **TLS ends at the reverse proxy.** The hop from the proxy to uvicorn stays on the server's loopback interface.
