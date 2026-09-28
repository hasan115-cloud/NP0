<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://ai.google.dev/static/site-assets/images/share-ais-513315318.png" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/527842af-703a-4390-ad08-98b5fcf6843f

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`

## Data persistence

PhishGuard stores enrolled systems, security rules, threat alerts, and the
complete URL browsing history reported by the extension. There are two
storage backends, and the server picks between them automatically:

- **No `DATABASE_URL` set (default).** Data is stored in local files under
  `data/` (`phishguard_db.json` for clients/rules/alerts, `url_events.jsonl`
  as an append-only log for URL history). This is correct and fast for a
  single, long-lived Node process — `npm run dev`, `npm start`, or any host
  that runs one persistent server instance (a normal VM, a Docker container,
  Cloud Run with `min-instances`/`max-instances` both set to 1, etc.).

- **`DATABASE_URL` set.** The server instead uses a real Postgres database
  (see `server/pgdb.ts`) — compatible with Supabase, Neon, Netlify DB, RDS,
  or any self-hosted Postgres. **This is required for correct behavior on
  Netlify Functions**, or any other deployment where more than one instance
  of the server can be running at once: each serverless function instance
  has its own independent filesystem, so local files written by one
  instance are invisible to a different instance that answers the next
  request — which is exactly what causes a dashboard count to look correct
  immediately after a write and then appear to drop on the very next
  refresh. Pointing every instance at the same external database removes
  that problem, because they all read and write the same rows.

  To use it, set `DATABASE_URL` to a standard Postgres connection string in
  your environment or Netlify site configuration. No other configuration
  is needed — the schema is created automatically on first connection
  (`CREATE TABLE IF NOT EXISTS`, safe to run on every cold start, and never
  destroys existing data). TLS is handled automatically for non-local hosts.

### Setting up Supabase as the database

1. Create a project at [supabase.com/dashboard](https://supabase.com/dashboard)
   (the free tier is enough for this app).
2. Open **Project Settings → Database** and, under **Connection string**,
   select the **Transaction pooler** tab (port `6543` — the right choice
   for Netlify Functions or any environment that can run many instances at
   once; a single long-lived process can instead use the **Session
   pooler** or the direct connection on port `5432`).
3. Copy the URI shown there — it looks like
   `postgresql://postgres.xxxxxxxxxxxx:[YOUR-PASSWORD]@aws-0-<region>.pooler.supabase.com:6543/postgres` —
   and substitute your actual database password for `[YOUR-PASSWORD]`
   (set when the project was created, or reset from that same page).
4. Set that full string as `DATABASE_URL`:
   - Locally, in a `.env` file (see `.env.example`).
   - On Netlify, in **Site settings → Environment variables**, so the
     deployed functions can see it too.
5. Start the server (or redeploy). The first request creates every table
   automatically — there is no separate migration step to run.
6. Every scan the extension performs (`/api/scan`, `/api/bulk-scan`,
   `/api/url-events`) now writes directly into your Supabase Postgres
   database, and the dashboard's Overview, URL History, Threat Alerts, and
   Reports views all read from those same rows.

`GET /api/info` reports a `persistenceWarning` field whenever the process is
running in a detected serverless environment (`NETLIFY` or
`AWS_LAMBDA_FUNCTION_NAME`) without `DATABASE_URL` set, so the risk is
diagnosable from the API itself rather than only showing up as inconsistent
dashboard counts.
