# PhishGuard Enterprise Security Hub

PhishGuard Enterprise Security Hub provides centralized security monitoring, telemetry, threat detection, policy management, and URL intelligence for PhishGuard Chrome Extensions across distributed workstations.

---

## Architecture Overview

```
Workstation A (Chrome Extension) ──┐
Workstation B (Chrome Extension) ──┼──> Vercel API (/api/*) ──> PostgreSQL / Supabase Database
Workstation C (Chrome Extension) ──┘           │
                                               ▼
                              Central Enterprise SOC Dashboard
```

- **Extension (Client MV3):** Intercepts navigations, performs local heuristic & policy evaluations, syncs rules from server, reports threat alerts, and streams durable URL telemetry.
- **Server (Vercel Serverless / Next.js):** REST API endpoints (`/api/scan`, `/api/url-events`, `/api/clients/*`, `/api/rules/*`, `/api/threats/*`, `/api/reports`) with full CORS support.
- **Database (PostgreSQL / Supabase):** Real persistent database storing enrolled systems, complete URL history, active threat alerts, whitelist rules, and phishing policies.

---

## Deploying to Vercel

### Step 1: Provision Database (PostgreSQL / Supabase)
1. In your [Supabase Dashboard](https://supabase.com/dashboard) (or Neon / Cloud SQL):
   - Go to **Project Settings → Database → Connection string**.
   - Select **Transaction pooler** (port `6543`), or copy the direct connection URI.
2. Formatted connection string:
   ```
   postgresql://postgres.[REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres?pgbouncer=true
   ```

### Step 2: Deploy to Vercel
1. Push your repository to GitHub / GitLab / Bitbucket.
2. In [Vercel Dashboard](https://vercel.com/dashboard), click **Add New → Project** and import the repository.
3. In **Settings → Environment Variables**, add:
   - `DATABASE_URL` = your Supabase connection string from Step 1.
   - `SUPABASE_URL` = (Optional) `https://[REF].supabase.co`
   - `SUPABASE_KEY` = (Optional) your Supabase service_role or API key
4. Click **Deploy**. Vercel will build and launch your production security hub.

The database tables (`clients`, `url_events`, `threat_alerts`, `whitelist_rules`, `phishing_rules`, `heartbeats`) are verified and initialized automatically on first request with `CREATE TABLE IF NOT EXISTS`.

---

## Enrolling Client Workstations

1. Open the deployed PhishGuard dashboard on any computer:
   `https://[your-app].vercel.app`
2. Navigate to **Install Extension** in the sidebar.
3. Click **Download Extension (.ZIP)**.
   - The server packages the Chrome Extension and injects the live production Vercel URL into `config.js`, `background.js`, `popup.js`, and `popup.html`.
4. On any user workstation:
   - Extract the downloaded ZIP.
   - In Google Chrome / Brave / Edge, navigate to `chrome://extensions`.
   - Enable **Developer mode** (toggle in top-right).
   - Click **Load unpacked** and select the unzipped folder.
5. The extension enrolls with your production server, pulls baseline security rules, and begins real-time protection.

---

## Local Development

```bash
# 1. Install dependencies
npm install

# 2. Run local development server (binds to 0.0.0.0:3000)
npm run dev

# 3. Build production bundle
npm run build

# 4. Type check / lint
npm run lint
```
