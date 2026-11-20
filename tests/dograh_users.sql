-- Test-only copy of the Dograh 1.48.0 users table (the columns the add-on touches).
CREATE TABLE users (
    id serial PRIMARY KEY,
    provider_id text UNIQUE NOT NULL,
    email text,
    password_hash text,
    selected_organization_id integer
);
CREATE UNIQUE INDEX ix_users_email_lower ON users (lower(email));
