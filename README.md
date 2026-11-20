# dograh-password-reset

A self-service "Forgot password?" flow for self-hosted [Dograh](https://github.com/dograh-hq/dograh), the open-source voice-agent platform. A user enters their email address, gets a single-use link by email, and sets a new password. No administrator is needed.

It is a separate add-on: Dograh's own code and compose file are not changed. The add-on runs as one container next to Dograh and reads Dograh's `users` table.

## What it does

- Sends a reset link that expires after 30 minutes by default and works once.
- Shows the same neutral message whether or not an account exists, and takes the same time either way.
- Sends a "your password was changed" email after each reset.
- Limits requests to 3 per email address and 10 per client address per hour.
- Stores only SHA-256 hashes of tokens, and bcrypt hashes of passwords (the same scheme Dograh uses).
- Includes an admin command for setting a password or printing a reset link.
- Optionally adds the "Forgot password?" link to Dograh's login page through a small nginx front.

## What it does not do

- It works only with Dograh's local login (`AUTH_PROVIDER=local`). It refuses to start otherwise.
- It does not sign out sessions that are already open. See [INSTALL.md, Limitations](INSTALL.md#limitations).
- It does not send email itself by default. It uses your SMTP account, or a signed webhook such as an n8n workflow.

## Status

Version 0.1.0. Tested against a Postgres copy of Dograh's `users` table, a stub of Dograh's health endpoint, and a real SMTP catcher. See [CHANGELOG.md](CHANGELOG.md).

## Getting started

Read [INSTALL.md](INSTALL.md). It covers the database role, the compose file, email, routing through Cloudflare or your own proxy, the optional login-page link, and a test you can run by hand.

## Files

| Path | What it is |
|---|---|
| `INSTALL.md` | Step-by-step installation, troubleshooting and uninstall |
| `SECURITY.md` | Security design, operator duties, how to report a vulnerability |
| `CHANGELOG.md` | Versions |
| `Dockerfile`, `pyproject.toml` | The add-on image (Python 3.12, non-root) |
| `dograh_password_reset/` | The application |
| `front/` | The optional nginx front and its settings |
| `examples/` | Compose override, grants, n8n workflow, Cloudflare Tunnel, Caddy and nginx examples |
| `tests/` | Test suite (pytest, real Postgres) and a front test |
| `run-tests.sh` | Runs the test suite in a throwaway Postgres container |

## Tests

```bash
./run-tests.sh
```

This starts a temporary Postgres container, runs the tests, and removes everything. It uses no host ports.

## Licence

BSD 2-Clause. See [LICENSE](LICENSE). Dograh is also BSD 2-Clause.
