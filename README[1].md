# Emergency Response Portal

PostgreSQL + Node/Express API + a single-file frontend (`frontend/index.html`).
The Express server also serves the frontend, so you only run one process.

```
emergency-portal/
├── database/   schema.sql, seed.sql
├── backend/    server.js, db.js, package.json, .env.example
├── frontend/   index.html   (HTML + CSS + JS, no build step)
└── README.md
```

## Requirements
- Node.js 18+
- PostgreSQL 12+ (the `pgcrypto` extension, included with standard installs)
- Internet access in the browser for the Leaflet map library and OpenStreetMap tiles

## Setup

1. **Database**
   ```bash
   createdb emergency_portal
   psql -d emergency_portal -f database/schema.sql
   psql -d emergency_portal -f database/seed.sql
   ```
   (Add `-U postgres` / `-h localhost` if needed. `schema.sql` drops and recreates the tables, so do not re-run it on real data.)

2. **Backend**
   ```bash
   cd backend
   npm install
   cp .env.example .env      # then edit DATABASE_URL and JWT_SECRET
   npm start
   ```

3. Open **http://localhost:3000**

## Test accounts (password for all: `Password@123`)

| Role       | Email                     | Opens          |
|------------|---------------------------|----------------|
| Admin      | admin@portal.test         | Dispatch, Admin |
| Dispatcher | dispatcher@portal.test    | Dispatch        |
| Responder  | ambulance@portal.test (also fire@ / police@) | My assignments |
| Citizen    | citizen@portal.test       | My reports      |

Sample tracking codes for the Track page: `DEMO000001`, `DEMO000002`, `DEMO000003`.

## Try this flow
1. As a visitor, click **Report Emergency**, submit a report, and note the tracking code.
2. Log in as `dispatcher@portal.test`, find the incident, click **Assign**, pick a responder.
3. Log in as that responder (e.g. `fire@portal.test`), press **On scene** then **Mark resolved**.
4. Open **Track** with the code to see the status timeline.

## API summary
| Method & path | Access |
|---|---|
| POST `/api/auth/register`, `/api/auth/login`; GET `/api/auth/me` | public / logged in |
| POST `/api/incidents` | public (anonymous allowed) |
| GET `/api/incidents/track/:code` | public (limited fields) |
| GET `/api/incidents/mine` | logged in |
| GET `/api/incidents?status=&type=&severity=`, GET `/api/incidents/:id` | dispatcher, admin (`:id` also the assigned responder) |
| PATCH `/api/incidents/:id/status` | dispatcher, admin, assigned responder |
| POST `/api/incidents/:id/assign` | dispatcher, admin |
| GET `/api/responders`, GET `/api/responders/me`, GET `/api/responders/me/assignments` | dispatcher/admin, responder |
| PATCH `/api/responders/:id/availability` | responder (own), dispatcher, admin |
| GET `/api/alerts` | public; POST/DELETE admin |
| GET `/api/contacts` | public; `/api/contacts/all`, POST, PUT, DELETE admin |
| GET `/api/admin/stats` | dispatcher, admin |
| GET/POST `/api/admin/users`, PATCH `/api/admin/users/:id` | admin |

## Security notes
- Passwords hashed with bcrypt; JWTs expire (default 8h); role and active status are re-checked on every request.
- All SQL is parameterized; all user text is HTML-escaped in the frontend.
- Rate limits on the API, login and the public report endpoint; `helmet` sets security headers and a CSP.
- Public registration only creates `citizen` accounts; admins create staff accounts.
- Before going live: use HTTPS, set a strong `JWT_SECRET`, delete the seed accounts, and set `app.set('trust proxy', 1)` if you run behind a reverse proxy (so rate limiting sees real client IPs).

## Notes
- The dispatcher dashboard refreshes every 10 seconds (polling). Socket.IO push updates can replace this later.
- Change `EMERGENCY_NUMBER` and `MAP_CENTER` at the top of the script in `frontend/index.html` for your region.

## Ideas for later
SMS alerts (Twilio), push notifications, offline report queue, multilingual UI (e.g. Hindi), live responder GPS tracking, incident photo uploads.
