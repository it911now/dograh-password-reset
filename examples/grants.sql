-- Database role for the password-reset add-on. Run once, as the Postgres superuser,
-- in Dograh's database. Stock Dograh's database is called "postgres" (POSTGRES_DB: postgres).
-- To check the name of yours:  docker compose exec postgres psql -U postgres -l
-- The file uses whatever database you connect to with -d, so only that -d value needs to match.
--
-- Copy this file into the database container and run it with a terminal attached,
-- because \password asks for the new password (nothing is echoed):
--   docker compose cp grants.sql postgres:/tmp/grants.sql
--   docker compose exec -it postgres psql -U postgres -d postgres -f /tmp/grants.sql

-- The login role. It owns nothing yet and is not a superuser.
CREATE ROLE dograh_password_reset LOGIN;
\password dograh_password_reset

-- At most 5 connections at once: the add-on's own limit (DB_POOL_SIZE, default 4) plus one for
-- the hourly clean-up. A bug or an attack on the add-on cannot use up Dograh's connections.
ALTER ROLE dograh_password_reset CONNECTION LIMIT 5;

-- Lets the role log in to this database.
SELECT current_database() AS dbname \gset
GRANT CONNECT ON DATABASE :"dbname" TO dograh_password_reset;

-- Lets the role look up objects in the public schema, where Dograh's users table lives.
-- It does not allow creating anything there.
GRANT USAGE ON SCHEMA public TO dograh_password_reset;

-- The add-on's own schema, created here by the superuser and owned by the role. The role therefore
-- needs no CREATE privilege on the database: it can create tables only inside this schema.
CREATE SCHEMA IF NOT EXISTS password_reset AUTHORIZATION dograh_password_reset;

-- Only the columns the add-on needs: find the account by email, and replace its password hash.
-- Read id, email and password_hash (the hash is read to tell accounts that have a local password
-- from accounts that do not).
GRANT SELECT (id, email, password_hash) ON public.users TO dograh_password_reset;
-- Change only the password hash, never the email or any other column.
GRANT UPDATE (password_hash) ON public.users TO dograh_password_reset;
