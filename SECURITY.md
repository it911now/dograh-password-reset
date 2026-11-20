# Security

## Reporting a vulnerability

Please report security problems privately. Use GitHub's private vulnerability reporting on this package's repository: open the **Security** tab and choose **Report a vulnerability**. Do not open a public issue for a vulnerability.

Include the add-on version, your Dograh version, the steps to reproduce and the impact you expect.

Supported versions: the latest release (0.1.0 at the time of writing).

## Design

- **Tokens.** A reset token is 32 random bytes, URL-safe. Only its SHA-256 is stored. It expires after `RESET_TOKEN_TTL_MINUTES` (30 by default) and works once. Requesting a new link invalidates the older unused links for that account.
- **No account enumeration.** The request form gives the same page and wording whether or not the address is an account. The response is sent before any lookup or email work, so timing does not reveal an account either. Rate-limited requests get the same page and send no email.
- **Rate limits.** 3 requests per email address and 10 per client address per hour. Both are counted in the add-on's own table, as hashes. The hashes are pseudonymous, not anonymous: anyone with database access who knows an email address or an IP address can compute its hash and check whether it appears. Concurrent requests are serialised, so a burst cannot get around the limit.
- **Passwords.** At least 12 characters, at most 72 bytes (bcrypt's limit), not equal to the email address, and confirmed. Hashed with bcrypt, as Dograh does.
- **Forms.** Every form has a CSRF token, which is checked against an `HttpOnly`, `SameSite=Lax` cookie. The cookie is `Secure` when `PUBLIC_BASE_URL` is https.
- **Headers.** Every page is sent with `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and a strict Content-Security-Policy (`default-src 'none'`).
- **Logs.** The add-on never logs tokens, passwords, full email addresses, SMTP passwords or webhook secrets. It logs a hash prefix of an address when it has to refer to one. The uvicorn access log is filtered so `token=` values are redacted.
- **Secrets.** Read only from files (`DATABASE_URL_FILE`, `SMTP_PASSWORD_FILE`, `MAIL_WEBHOOK_SECRET_FILE`), never from plain environment values in the compose file.
- **Webhook signatures.** Each webhook request carries `X-Dograh-Reset-Signature: sha256=<HMAC-SHA256 of the raw body>`. The example n8n workflow checks it with a constant-time comparison. The signature has no timestamp or nonce, so anyone who captures a signed request can replay it. A replay re-sends the same email to the same recipient; it cannot change the recipient or the content.
- **Least privilege.** The add-on's database role can read three columns of `users` and change one. It cannot read other tables or other columns, and it has no `CREATE` on the database: an administrator creates its schema, `password_reset`, owned by the role. It is limited to 5 connections, and the add-on itself uses at most `DB_POOL_SIZE` (4) at a time (see `examples/grants.sql`).
- **Container.** Runs as a non-root user (uid 10001). Listens on port 8080 inside Docker only. The compose example publishes it on `127.0.0.1` only.
- **Start-up checks.** It refuses to start unless Dograh's health endpoint reports `auth_provider: local` and the `users` table has the columns it needs.

## Duties for the operator

- **Reset links carry a token in the URL.** A reverse proxy, a tunnel or Cloudflare can log that URL, and the token is then in plain text in your logs. Keep those logs off for `/password-reset/new`, or redact `token=`. The examples in `examples/` and the nginx front do this. Read the log retention on your proxy, tunnel and CDN as well.
- **`TRUST_CLOUDFLARE=true` only when the add-on is reachable solely through the Cloudflare tunnel.** The add-on is published on `127.0.0.1` only. If anything else can reach it, a client can send its own `CF-Connecting-IP` and get around the per-address limits.
- **`TRUSTED_PROXIES` lists only proxies you run.** Anyone who can send requests from a listed range can set `X-Forwarded-For`.
- **`FORWARDED_PROTO`.** Behind a TLS-terminating tunnel, the front passes the tunnel's `X-Forwarded-Proto`. If the front could ever be reached directly, set `FORWARDED_PROTO=https` so a client cannot send a fake value.
- **`BASE_PATH` must not be `/`** when you use the front. The front's routes depend on a sub-path.
- **Sibling subdomains.** The CSRF cookie belongs to the host, and cookies can be set from any subdomain. If other subdomains of your domain are not trusted by you, serve Dograh on its own registrable domain (cookie tossing).
- **Secret files.** Put them in a folder only you can read (`chmod 700`). The files must be readable by the container user (`chmod 644`), so the folder is the protection.
- **Sessions.** A password reset does not end sessions already open. Dograh cannot revoke its JWTs. Those sessions end at their normal expiry (`OSS_JWT_EXPIRY_HOURS` in Dograh). Shortening that setting affects every session, so it is a trade-off for you to make.
- **n8n.** The Code node needs `NODE_FUNCTION_ALLOW_BUILTIN=crypto` and the shared secret in `DOGRAH_RESET_WEBHOOK_SECRET`. Keep the secret out of workflow exports.
- **Do not store reset links in n8n or in a mailbox.** The webhook body contains the reset link. Turn execution saving off for this workflow (the example sets `saveDataSuccessExecution` and `saveDataErrorExecution` to `none` and `saveManualExecutions` to `false`) and do not keep sent copies of the mail (for Microsoft Graph, `saveToSentItems: false`).

## Known limitations

- Only `AUTH_PROVIDER=local`.
- The admin command (`dograh-reset set-password`) does not send the "password changed" email.
- No common-password check beyond the length and email rules.
- A failed email send is logged by error class only, so the reason is not in the log. The user still sees the neutral page.
