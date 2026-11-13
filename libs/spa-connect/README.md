# spa-connect

`spa` connects a project folder to a shared **Secure Prompt Assistant** server. You scan your code, get a linted
remediation prompt for each finding to paste into your coding assistant, and have the server verify your fix
independently. You need no scanners and no model on your machine, and the package depends on nothing outside the
Python standard library (3.10+).

```bash
pip install ./libs/spa-connect                    # from the main repository; installs the `spa` command
cd path/to/your-project
spa connect --server https://spa.example.edu      # paste the access token from your administrator (hidden)
spa scan --label "before the fix"
spa findings
spa prompt 5 > prompt.txt                         # paste into your assistant, review its change
spa verify 5                                      # exit 0 only when the fix is VERIFIED_RESOLVED
spa disconnect
```

- **Your token** is kept in your user config directory (`%APPDATA%\spa\` or `~/.config/spa/`, owner-only). It is
  never written into the project, and never taken as a command-line argument. In CI, pipe it in with `--token-stdin`
  or set `SPA_TOKEN`.
- **What is sent:** for a scan, the folder without version-control data, virtual environments, dependency caches,
  local `.env` files, links and anything in `.spaignore`. For a prompt, only the one file the finding is in. The
  server deletes both once it has used them.
- **Transport:** https only, with certificates verified; `http://` is allowed to 127.0.0.1 only. Redirects are never
  followed, so the token cannot be carried to another address. Set `SPA_CA_FILE` if your server uses an in-house
  certificate authority.

The full guide covers server setup, token administration, the security controls and the limits:
[`docs/deployment.md`](../../docs/deployment.md).

MIT licence.
