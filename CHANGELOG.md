# Changelog

## 0.1.0

First release.

- Self-service reset: request form, single-use emailed link (30 minutes by default), new-password form, "password changed" notice.
- Neutral responses and matching timing for unknown addresses. Rate limits per email (3 per hour) and per client address (10 per hour).
- Email by SMTP, or by a signed webhook (example n8n workflow included).
- Admin command: `dograh-reset set-password` (password from stdin) and `dograh-reset generate-link`.
- Start-up checks: Dograh must report `auth_provider: local`, and the `users` table must have the required columns.
- Optional nginx front that adds a "Forgot password?" link to Dograh's login page.
- Examples: compose override, database grants, Cloudflare Tunnel ingress, Caddy and nginx reverse proxies.
- Least privilege: an administrator creates the `password_reset` schema for the role (no `CREATE` on the database); the role has a connection limit; `DB_POOL_SIZE` bounds the add-on's own connections.
- Pinned build: Python patch tag and `constraints.txt`; `base` is the Dockerfile's default stage.
- Logs: uvicorn tracebacks and configuration errors never carry exception text or setting values.
