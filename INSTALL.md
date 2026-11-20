# Install the Dograh password-reset add-on

This guide adds a "Forgot password?" flow to a self-hosted [Dograh](https://github.com/dograh-hq/dograh) install that uses local login. A user enters their email, gets a link, and sets a new password. Nobody has to ask an administrator.

The guide follows the order you will do things in. Every step is a command or a file you can check. Steps 1 to 3 are required. Step 4 depends on how your site is reached. Step 5 is optional. Step 6 tests the result.

## Requirements

- **Dograh with local login.** `GET /api/v1/health` must report `"auth_provider": "local"`. The add-on refuses to start otherwise.
- **Docker Compose v2**, and the Dograh compose project you already run.
- **A way to send email**: an SMTP account (Microsoft 365, Google Workspace, or any relay), or an HTTPS endpoint that sends the email for you (for example an n8n workflow; see [examples/n8n-send-reset-mail.json](examples/n8n-send-reset-mail.json)).
- **A public https address** for Dograh, for example `https://dograh.example.com`. Reset links point at it. Local testing on `http://localhost` also works.
- **Access to Dograh's database as the Postgres superuser**, once, for step 1.

The add-on reads only three columns of Dograh's `users` table (`id`, `email`, `password_hash`) and checks them on every start. It was written against the Dograh 1.48.0 schema.

The names used below are examples. Replace them with yours:

| Example | Meaning |
|---|---|
| `dograh.example.com` | the public address of Dograh |
| `postgres`, `api`, `ui` | the service names in Dograh's compose file |
| `postgres` (database) | the name of Dograh's database. Stock Dograh uses `postgres` (`POSTGRES_DB: postgres`). Check yours: `docker compose exec postgres psql -U postgres -l` |
| `reset-sender@example.com` | the mailbox that sends reset emails |

---

## 1. Create the database role

The add-on connects with its own database role. It does not use Dograh's superuser. The role can read three columns of `users` and change one. It owns its own schema, `password_reset`, which holds its tokens and rate-limit records. The superuser creates that schema for it (in the same script), so the role needs no permission to create anything else in the database. The role is limited to 5 connections. Nothing else in Dograh's database is touched.

Pick a password for the role, for example from `openssl rand -hex 24`. You will type it twice here and once more in step 2.

From the folder that holds Dograh's `docker-compose.yaml`, with the package copied to `./password-reset` (see step 2). The commands use Dograh's stock database name, `postgres`. To check yours, run `docker compose exec postgres psql -U postgres -l`, and use that name in place of `postgres` after `-d` and in step 2c.

```bash
docker compose cp password-reset/examples/grants.sql postgres:/tmp/grants.sql
docker compose exec -it postgres psql -U postgres -d postgres -f /tmp/grants.sql
```

psql asks for the new role's password and does not echo it. Then it runs the remaining statements and prints `ALTER ROLE`, `GRANT`, `CREATE SCHEMA` and `GRANT` lines. If you see `ERROR`, stop and read the message. The statements, each with a comment, are in [examples/grants.sql](examples/grants.sql).

Check that the role can read what it needs and nothing more:

```bash
docker compose exec -it postgres psql -U postgres -d postgres -c "\dp users"
docker compose exec -it postgres psql -U postgres -d postgres -c "\dn password_reset"
```

The first output should list `dograh_password_reset` under the column privileges of `users`: `r` (select) on `id`, `email` and `password_hash`, and `w` (update) on `password_hash` (shown together as `rw`). No other column. The second shows the schema `password_reset` with owner `dograh_password_reset`.

---

## 2. Add the compose block

The add-on runs in its own compose file, so Dograh's stock `docker-compose.yaml` is not changed.

**2a. Copy the package.** Copy the package folder, `password-reset/`, into the folder with Dograh's compose file, so you have `./password-reset/Dockerfile` and `./password-reset/front/`.

If you will use the front (step 5), make its start script executable now:

```bash
chmod +x password-reset/front/defaults.envsh
```

nginx runs only executable files in `/docker-entrypoint.d/`. Without the `chmod`, the front starts without its default settings, its configuration is invalid, and the whole Dograh UI answers `502`.

**2b. Copy the override file** next to Dograh's compose file:

```bash
cp password-reset/examples/docker-compose.password-reset.yaml ./
```

**2c. Create the two secret files.** They hold the database URL and the SMTP password. They are plain files, not environment variables, so they do not appear in `docker compose config` or `docker inspect`.

```bash
mkdir -p secrets
chmod 700 secrets
```

Create `secrets/password-reset-db-url` with one line, using the role's password from step 1:

```
postgresql://dograh_password_reset:YOUR-ROLE-PASSWORD@postgres:5432/postgres
```

(`postgres:5432` is the database service and its port. The last `postgres` is the database name from step 1.)

Create `secrets/password-reset-smtp-password` containing only the SMTP password. If your relay needs no login, see step 3.

```bash
chmod 644 secrets/password-reset-db-url secrets/password-reset-smtp-password
```

The container runs as a non-root user, so it must be able to read the files. The folder is `700`, so other users on the host still cannot reach them. If you use `chmod 600` on the files, the add-on fails at start with `DATABASE_URL_FILE: cannot read /run/secrets/db_url: Permission denied`.

**2d. Edit the settings** in `docker-compose.password-reset.yaml`. Every line marked `# EDIT` needs your values. The file also names the service it expects from your compose file (`api`, `postgres`). Check that those names exist:

```bash
docker compose config --services
```

The settings the add-on reads are these:

| Setting | Default | Meaning |
|---|---|---|
| `DATABASE_URL_FILE` | (required) | File with the database URL. Mounted as a secret. |
| `DOGRAH_API_URL` | (required) | Internal URL of Dograh's API, for example `http://api:8000`. Used once at start to check the login mode. |
| `PUBLIC_BASE_URL` | (required) | Public address of Dograh, `https://` (or `http://localhost` for tests). Reset links are built from it. |
| `BASE_PATH` | `/password-reset` | Path the pages are served under. **Must not be `/` when you use the front** (step 5). |
| `DOGRAH_LOGIN_PATH` | `/auth/login` | Dograh's login page. Used for the "Back to sign in" links. |
| `RESET_TOKEN_TTL_MINUTES` | `30` | How long a reset link works. It is single use. |
| `MAIL_TRANSPORT` | (required) | `smtp` or `webhook` (step 3). |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_STARTTLS`, `SMTP_USERNAME`, `SMTP_PASSWORD_FILE` | `587`, `true` | SMTP settings (step 3). |
| `MAIL_FROM` | (required for smtp) | The From address, for example `Dograh <reset-sender@example.com>`. |
| `MAIL_WEBHOOK_URL`, `MAIL_WEBHOOK_SECRET_FILE` | (required for webhook) | The webhook option (step 3). |
| `PRODUCT_NAME` | `Dograh` | Name shown in the pages and emails. |
| `SUPPORT_TEXT` | empty | An optional line added to pages and emails, for example a support address. |
| `TRUST_CLOUDFLARE` | `false` | Read the visitor address from `CF-Connecting-IP`. Only with step 4A, see below. |
| `TRUSTED_PROXIES` | empty | Comma-separated address ranges of proxies you run. Only with step 4B. |
| `DB_POOL_SIZE` | `4` | Most database connections the add-on uses at once (1 to 50). A request that cannot get one within 3 seconds gets a "busy" page (503); the request form still shows its normal page. Keep it below the role's `CONNECTION LIMIT` (5 in `grants.sql`). |

**`TRUST_CLOUDFLARE=true`** only when the add-on can be reached solely through the Cloudflare tunnel. The compose file publishes the add-on on `127.0.0.1` only, so the tunnel is the only path from outside. If anything else can reach the add-on's port, a client can send its own `CF-Connecting-IP` header and get around the per-address limits. Leave it `false` in any other setup.

**`TRUSTED_PROXIES`** is for a reverse proxy you run yourself (step 4B). Add only the range the proxy's requests come from, for example the Docker network (`172.16.0.0/12` covers Docker's default networks). Do not add ranges you do not control.

**2e. Start the add-on:**

```bash
docker compose -f docker-compose.yaml -f docker-compose.password-reset.yaml up -d --build password-reset
docker compose -f docker-compose.yaml -f docker-compose.password-reset.yaml logs password-reset
```

The log should end with a line like `dograh-password-reset ready (dograh 1.48.0)`. If it does not, the container restarts. Look at the last error and check the [Troubleshooting](#troubleshooting) section. The container listens only inside Docker and on `127.0.0.1:8081`.

---

## 3. Choose how email is sent

Pick one. The rest of the setup is the same.

### 3A. SMTP (the default)

Set `MAIL_TRANSPORT: smtp` and the `SMTP_*` settings in the override file, and put the SMTP password in `secrets/password-reset-smtp-password`.

Examples:

- **Microsoft 365**: `SMTP_HOST: smtp.office365.com`, `SMTP_PORT: "587"`, `SMTP_STARTTLS: "true"`, with the mailbox as `SMTP_USERNAME`. The mailbox must allow SMTP AUTH. Microsoft is phasing out basic SMTP AUTH in some tenants. If yours refuses it, use 3B.
- **Google Workspace**: `SMTP_HOST: smtp.gmail.com`, `SMTP_PORT: "587"`, `SMTP_STARTTLS: "true"`, with an app password as the secret.
- **Relay with no login** (for example an internal relay on port 25): set `SMTP_STARTTLS: "false"` if it has no TLS, leave `SMTP_USERNAME` empty, and delete the `SMTP_PASSWORD_FILE` line and the `smtp_password` secret from the override file.

The password is read only from the secret file. Never put it in the compose file.

### 3B. Webhook (for example n8n)

Set `MAIL_TRANSPORT: webhook` and `MAIL_WEBHOOK_URL` to your endpoint in the override file. Remove the `SMTP_*` and `MAIL_FROM` lines. Remove `smtp_password` in both places: from the `secrets:` list under the `password-reset` service, and from the top-level `secrets:` block at the bottom of the file.

Create `secrets/password-reset-webhook-secret` (mode `644`) containing a random secret, for example from `openssl rand -hex 32`. Then wire it in the override file, because the compose file does not mount it by default. **Merge the snippet into the blocks that already exist in the file.** Do not add a second `services:` or `secrets:` key (YAML would keep only one of them). Under `password-reset`, add the `MAIL_WEBHOOK_SECRET_FILE` line to `environment:` and use the `secrets:` list below instead of the existing one. In the top-level `secrets:` block, add `webhook_secret` next to `db_url`:

```yaml
services:
  password-reset:
    environment:
      MAIL_WEBHOOK_SECRET_FILE: /run/secrets/webhook_secret
    secrets:
      - db_url
      - webhook_secret
secrets:
  webhook_secret:
    file: ./secrets/password-reset-webhook-secret
```

Run `docker compose -f docker-compose.yaml -f docker-compose.password-reset.yaml config --quiet` to check the file. It prints nothing when the file is valid.

The add-on POSTs JSON `{to, subject, text, html, kind}` and signs the raw body. The header `X-Dograh-Reset-Signature: sha256=<hex>` is the HMAC-SHA256 of the body with your secret. Any 2xx answer means sent.

The example workflow, [examples/n8n-send-reset-mail.json](examples/n8n-send-reset-mail.json), checks the signature and sends the mail through n8n's SMTP credential. To use it:

1. In n8n, import the file and open **Send Email**. Choose your SMTP credential and set the From address. The file's settings turn off saving of executions, because the webhook body contains the reset link. Keep them off (see [SECURITY.md](SECURITY.md)).
2. Set the n8n environment variables `NODE_FUNCTION_ALLOW_BUILTIN=crypto` (the Code node uses Node's `crypto`) and `DOGRAH_RESET_WEBHOOK_SECRET` (the same value as the secret file). Restart n8n.
3. Activate the workflow. Its production URL is `https://<your-n8n>/webhook/dograh-password-reset`. Put that in `MAIL_WEBHOOK_URL`.

Test the signature path before you rely on it: a request without the correct header must get `401`, and the step 6 reset must produce an email.

---

## 4. Route traffic to the add-on

The reset pages must be reachable at `https://dograh.example.com/password-reset/`. Pick the option that matches your site.

Two rules apply to all options:

- **Reset links carry a token in the URL.** Anything that logs full URLs, including a tunnel, a reverse proxy or the nginx front, records the token. The add-on redacts its own log. For everything else, keep access logs off for `/password-reset/new`, or redact the `token=` query. The examples below do this. Error logs of nginx can also show a request line on upstream errors, so keep those private too.
- **Use an https address.** The reset link and the session cookie use the public address from `PUBLIC_BASE_URL`.

### 4A. Cloudflare Tunnel

The add-on's port is on `127.0.0.1:8081` and the front's is on `127.0.0.1:8088` (step 5). The tunnel sends `/password-reset/` to the add-on and everything else to the front. Add these rules to your tunnel config, for example `/etc/cloudflared/config.yml`. [examples/cloudflared-config.yml](examples/cloudflared-config.yml) shows the whole file.

```yaml
ingress:
  # Your existing Dograh rules, for example /api/v1/, go here, above the catch-all.
  - hostname: dograh.example.com
    path: ^/password-reset/
    service: http://127.0.0.1:8081
  - hostname: dograh.example.com
    service: http://127.0.0.1:8088
  - service: http_status:404
```

The order matters. Cloudflare takes the first rule that matches, so the reset path must come above the catch-all. Restart `cloudflared` after editing.

Set `TRUST_CLOUDFLARE: "true"` in the override file and restart the add-on. Do this only because the add-on is reachable only through the tunnel (see step 2d).

Cloudflare Access protects the whole hostname. Choose one of two setups:

**Option 1: keep Access on everything (recommended).** Only people who can pass Access can open the reset pages. This is the safest option. The emailed link also goes through Access, so the user must pass Access before they can set a password. Use this when your Dograh users are a known list, for example staff.

**Option 2: public reset pages.** Anyone on the internet can reach the reset pages, so the rate limits are the only brake.

1. In Cloudflare Zero Trust, add an Access application with a **Bypass** policy that includes everyone, for both paths: `dograh.example.com/password-reset` (the bare path, which the front also serves) and `dograh.example.com/password-reset/*`. A rule for `/password-reset/*` alone leaves the bare path behind the Access login.
2. Keep `TRUST_CLOUDFLARE: "true"` (the add-on then sees the real visitor address).
3. Add a WAF rate-limiting rule (Security > WAF > Rate limiting rules in the Cloudflare dashboard; the menu names change, so look for "rate limiting") for `POST` requests to `/password-reset/request`, for example 10 requests per 10 minutes per IP address, with a block action. This sits in front of the add-on's own limits.

Cloudflare's own logs (Logpush and Access logs) also record full URLs, and so the token. Keep them off for this path.

### 4B. Without Cloudflare (Caddy or nginx)

Route the whole hostname to the front (step 5), and let your proxy terminate TLS. The examples below do that.

**Without the front** (no "Forgot password?" link, so users must be told the address `https://dograh.example.com/password-reset/`), the proxy itself does the split: `/password-reset` and `/password-reset/...` go to the add-on (`127.0.0.1:8081`), everything else goes to Dograh's UI (the host port the UI is published on, `3010` in stock Dograh). In Caddy:

```
dograh.example.com {
    @reset path /password-reset /password-reset/*
    reverse_proxy @reset 127.0.0.1:8081
    reverse_proxy 127.0.0.1:3010
}
```

In nginx, add two `location` blocks to the `server` block that already proxies the UI. Each sends the request to the add-on: `location = /password-reset { proxy_pass http://127.0.0.1:8081; }` and `location /password-reset/ { proxy_pass http://127.0.0.1:8081; }`, both with the same `proxy_set_header Host`, `X-Forwarded-For` and `X-Forwarded-Proto` lines as the UI location. (A `proxy_pass` without a URI part passes the path on unchanged, which the add-on expects.) Keep the token out of the access log as in the examples. Set `BASE_PATH` as before, and `TRUSTED_PROXIES` as below.

- **Caddy**: [examples/Caddyfile](examples/Caddyfile). Caddy gets the certificate itself, and the example redacts `token` from its access log.
- **nginx**: [examples/nginx-reverse-proxy.conf](examples/nginx-reverse-proxy.conf). Replace the certificate paths.

Without Cloudflare the visitor address comes from `X-Forwarded-For`. Set `TRUSTED_PROXIES` in the override file to the range your proxy's requests come from. If your proxy runs on the same host as the Docker containers, that is usually the Docker network range, for example `172.16.0.0/12`. Check the actual range with `docker network inspect <network>`. If you leave it empty, every visitor looks like the proxy, so the 10-per-hour address limit applies to all visitors together.

Set `TRUST_CLOUDFLARE: "false"` in this setup.

### Cookies and sibling subdomains

The reset form uses a CSRF cookie scoped to the path `/password-reset/`. If other subdomains of the same domain are not trusted (a shared hosting account, a marketing site someone else runs), an attacker on that subdomain can set cookies for the whole domain, which can defeat the form protection. Serve Dograh on its own registrable domain, for example `dograh-example.com` rather than `staff.example.com`, if you cannot control the other subdomains.

---

## 5. Optional: add the "Forgot password?" link (nginx front)

Dograh's UI cannot be changed, so the front adds a script to every HTML page. The script puts a "Forgot password?" link under the sign-in form. The front proxies everything else to Dograh's UI unchanged, including websockets. If the front is not running, users go to `https://dograh.example.com/password-reset/` directly, and nothing else breaks.

The front is already in the override file. Make sure the password-reset add-on is running, then start the front:

```bash
docker compose -f docker-compose.yaml -f docker-compose.password-reset.yaml up -d password-reset-front
```

The front's environment has five settings (the image's entrypoint reads the defaults file, so you normally change nothing):

| Variable | Default | Notes |
|---|---|---|
| `UI_UPSTREAM` | `ui:3010` | Dograh's UI. Change if your UI service or port differs. |
| `RESET_UPSTREAM` | `password-reset:8080` | The add-on. |
| `BASE_PATH` | `/password-reset` | Must match the add-on's `BASE_PATH`, and must not be `/`. |
| `FORWARDED_PROTO` | empty | See below. |
| `RESOLVER` | the container's resolver | DNS server for the service names. |

**`FORWARDED_PROTO`.** When the front is behind a TLS-terminating tunnel or proxy, that proxy sends `X-Forwarded-Proto: https`, and the front passes it on. Leave `FORWARDED_PROTO` empty for that. If the front could ever be reached directly from the internet, set `FORWARDED_PROTO: https` so a client cannot send a fake value. The front then uses that value every time.

**Check the front**: open `https://dograh.example.com/auth/login`, scroll under the sign-in form, and see "Forgot password?". Then click it: it must open the request form.

If Dograh's login form does not show the link, check the page source for `<script src="/password-reset/inject.js" defer>` just before `</body>`. If it is missing, the request is not going through the front.

The front's health check uses `http://127.0.0.1/__front_health`, which nginx answers itself (`204`). It does not depend on Dograh's UI or the add-on.

---

## 6. Test it

Run these checks in order. Each one should pass before you go on.

**a. The add-on is up** (through the tunnel or proxy):

```bash
curl -s https://dograh.example.com/password-reset/healthz
```

The answer is `ok`. A `503` means the add-on cannot reach its database.

**b. The request page works.** Open `https://dograh.example.com/password-reset/` in a browser. You see a form with one email field.

**c. Unknown addresses look the same.** Enter an address that is not a Dograh account. The page says:

> If an account exists for that address, a link is on its way. It expires in 30 minutes.

No email is sent. Then enter the address of a real account: the page shows the same message, so the form does not reveal which addresses have accounts.

**d. A reset works end to end.** Enter the email address of a real Dograh account (use a test account if you can). Then:

1. The reset email arrives. Open the link in it.
2. Set a new password of at least 12 characters, not equal to the email address, and type it twice.
3. The page shows "Password changed". The add-on sends a second email: "Your Dograh password was changed".
4. Sign in to Dograh with the new password.

**e. The link works only once.** Open the same reset link again. It must show "This link is not valid", with the line "It has expired or has already been used. Request a new one and try again."

**f. The rate limit works.** Submit the request form four times for the same address within an hour. The page is the same every time. Three emails arrive, and the fourth request sends none.

If any check fails, see [Troubleshooting](#troubleshooting).

---

## Admin reset from the command line

Use this when email is down or a user cannot receive it. The admin command runs inside the add-on container.

**Set a password directly.** The new password is read from standard input, never from the command line, so it does not reach your shell history. Use `read -s` so nothing is echoed:

```bash
read -rs NEWPW
printf '%s' "$NEWPW" | docker compose -f docker-compose.yaml -f docker-compose.password-reset.yaml exec -T password-reset dograh-reset set-password user@example.com
unset NEWPW
```

The command prints `Password updated.` It also cancels any open reset links for that account. It follows the same rules as the form: at least 12 characters, not the email address. It does **not** send the "password was changed" email.

Piping is required. If you type the password at a prompt in a terminal, the terminal echoes it.

**Print a one-time reset link** for an admin to pass on:

```bash
docker compose -f docker-compose.yaml -f docker-compose.password-reset.yaml exec password-reset dograh-reset generate-link user@example.com
```

The command prints a link valid for the normal time (30 minutes by default) and only once. Treat it like a password: send it only to the account's owner, and do not paste it into a ticket that others can read.

---

## Troubleshooting

Look at the container log first: `docker compose -f docker-compose.yaml -f docker-compose.password-reset.yaml logs --tail=50 password-reset`.

| Message in the log | Cause and fix |
|---|---|
| `Dograh auth_provider is not 'local'; this add-on only supports local login.` | Dograh uses another login provider. This add-on works only with `AUTH_PROVIDER=local`. |
| `Dograh health check failed after 5 tries (ConnectError).` | The add-on cannot reach `DOGRAH_API_URL`. Check the service name and port, and that the API is running. `HTTP 404` or `HTTP 503` means the URL points at the wrong service or the API is unhealthy. |
| `Dograh users table is missing columns: ...` | The grants in step 1 are missing, or Dograh's schema changed. Run `\dp users` as in step 1. |
| `Schema password_reset is missing or not owned by this role, and the role may not create it.` | Step 1 did not finish. As the superuser run `CREATE SCHEMA IF NOT EXISTS password_reset AUTHORIZATION dograh_password_reset;` (an existing schema that another role owns: `ALTER SCHEMA password_reset OWNER TO dograh_password_reset;`). |
| `password authentication failed` or `too many connections for role "dograh_password_reset"` (in an error class name such as `OperationalError`) | The password in the db-url secret is wrong, or the role's 5-connection limit is used up. Check the secret, and keep `DB_POOL_SIZE` below the limit. Visitors see "The service is busy" (503) meanwhile. |
| `DATABASE_URL_FILE: cannot read /run/secrets/db_url: Permission denied` | Set the secret files to mode `644` (step 2c). |
| `DATABASE_URL_FILE: file ... is empty` (or the same for another `*_FILE`) | The secret file has no content. |
| `<SETTING> is required` | A required setting is missing from the override file. The message names it. |
| `PUBLIC_BASE_URL must be an https URL` | Use `https://` (or `http://localhost` only for tests). |
| `BASE_PATH must start with '/'` | Fix the path, for example `/password-reset`. |
| `MAIL_TRANSPORT must be 'smtp' or 'webhook'` | Fix the value. |
| `password reset email not sent: kind=reset ... error=MailError` | The email could not be handed to the transport. The log shows only the error class, on purpose, because SMTP and webhook errors can contain addresses. Check `SMTP_HOST`, `SMTP_PORT`, `SMTP_STARTTLS`, the username and the password file, or the webhook URL and secret. Send one test reset and watch the log. |
| The form shows "Invalid form submission. Reload the page and try again." | The CSRF cookie is missing or expired (one hour). Reload the page. If it keeps happening, the browser blocks cookies for the path, or the page is served from a different address than `PUBLIC_BASE_URL`. |
| The reset link shows "This link is not valid." | The link is older than `RESET_TOKEN_TTL_MINUTES`, it was already used, or a newer link was requested after it (which cancels the older ones). Request a new one. |
| "Forgot password?" is missing from the login page | Step 5 is not running, or the front does not see the page. Check for the script tag in the page source. |
| `502 Bad Gateway` on the whole site after step 5 | The front cannot reach the UI. Check `UI_UPSTREAM` and that the UI service is running. The front itself is fine. |
| Every visitor hits the 10-per-hour address limit | The add-on sees the proxy's address for all visitors. Set `TRUST_CLOUDFLARE` (tunnel) or `TRUSTED_PROXIES` (your proxy). |

---

## Limitations

- **Open sessions stay signed in.** Dograh signs in users with stateless tokens (JWTs) that it cannot revoke. A password reset does not sign out sessions that are already open. They end when their token expires (Dograh's `OSS_JWT_EXPIRY_HOURS`). A password change does stop the next sign-in with the old password.
- **Local login only.** The add-on refuses to start when Dograh uses another login provider.
- **No common-password check.** The add-on enforces the length and email rules only. Choose a stricter policy in Dograh if you need one.
- **The admin command does not send the "password was changed" email.**
- **Email delivery is outside the add-on.** If mail does not arrive, the user still sees the neutral page. Check the log (step 6) and your mail system.

---

## Uninstall

From the folder with Dograh's compose file:

```bash
docker compose -f docker-compose.yaml -f docker-compose.password-reset.yaml stop password-reset password-reset-front
docker compose -f docker-compose.yaml -f docker-compose.password-reset.yaml rm -f password-reset password-reset-front
```

Remove the add-on's schema and role from Dograh's database (this drops the `password_reset` schema with the reset tokens and rate-limit records, and nothing else):

```bash
docker compose exec -it postgres psql -U postgres -d postgres -c "DROP OWNED BY dograh_password_reset; DROP ROLE dograh_password_reset;"
```

Remove `docker-compose.password-reset.yaml`, the `password-reset/` folder, the `secrets/password-reset-*` files and the tunnel or proxy rules from step 4. Dograh's own `docker-compose.yaml` was never changed, so it needs nothing.
