# Sentinel — Security Threat Monitoring Dashboard

A full-stack college group project demonstrating a defensive security dashboard. It includes a responsive frontend, Express REST API, threat-event CRUD, dashboard statistics, filters, severity charts, and optional MongoDB storage.

> **Important:** This is a demo using sample events. It does not inspect real network traffic, scan devices, detect live attacks, or replace a production SIEM/security product.

## Features

- Responsive dashboard with total, open, critical, and resolved threat counters
- Severity distribution chart, response-status donut, and category analytics
- Threat list with search and filters for severity, status, and type
- Add threat events, update status, and delete demo events
- REST API built with Node.js and Express
- Input validation, JSON body size limit, Helmet security headers, and API rate limiting
- Local JSON storage works without a database; optional MongoDB support
- Sample threat records loaded automatically on first run

## Requirements

- Node.js 18 or later
- npm
- Optional: MongoDB Community Server or MongoDB Atlas connection string

## Run locally

1. Extract the project ZIP and open the `security-threat-monitor` folder in IntelliJ IDEA or VS Code.
2. Open the terminal in that folder.
3. Install dependencies:

   ```bash
   npm install
   ```

4. Start the app:

   ```bash
   npm start
   ```

5. Open **http://localhost:3000** in your browser.

The first run creates `data/threats.json` with sample events. New events and status changes persist locally in that file. Keep this file out of public Git repositories if it contains real information.

## Optional MongoDB setup

By default, the app uses local JSON storage, so MongoDB is not required for the demo.

To use MongoDB, set environment variables before starting the app:

**Windows PowerShell**
```powershell
$env:MONGODB_URI="mongodb://127.0.0.1:27017"
$env:MONGODB_DB="security_monitor"
npm start
```

**macOS/Linux**
```bash
export MONGODB_URI="mongodb://127.0.0.1:27017"
export MONGODB_DB="security_monitor"
npm start
```

For MongoDB Atlas, use your own connection string as `MONGODB_URI`. Never commit credentials or `.env` files to GitHub. If the database connection fails, the app falls back to local JSON storage.

## API reference

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | API health and storage mode |
| GET | `/api/stats` | Dashboard counts and breakdowns |
| GET | `/api/threats` | List threat events |
| GET | `/api/threats?severity=High` | Filter by severity |
| GET | `/api/threats?status=Open` | Filter by status |
| GET | `/api/threats?search=login` | Search events |
| POST | `/api/threats` | Create a threat event |
| PATCH | `/api/threats/:id` | Update status or severity |
| DELETE | `/api/threats/:id` | Delete a demo event |

Example POST JSON:
```json
{
  "title": "Repeated failed login attempts",
  "sourceIp": "192.0.2.10",
  "type": "Authentication",
  "severity": "High",
  "asset": "Admin Portal",
  "description": "Sample event for demonstration."
}
```

Documentation-only IP ranges such as `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` are used in examples.

## Project structure

```text
security-threat-monitor/
├── public/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── data/
├── .env.example
├── .gitignore
├── package.json
├── server.js
└── README.md
```

## Suggested group presentation split

- **Member 1 — Frontend:** HTML structure, CSS layout, responsive design
- **Member 2 — Dashboard logic:** JavaScript rendering, search, filters, charts
- **Member 3 — Backend:** Express server, REST endpoints, validation
- **Member 4 — Database & testing:** MongoDB/local JSON storage, API testing, documentation

## Limitations and future enhancements

- Replace sample events with authorized telemetry from a real, approved data source.
- Add authenticated user accounts and role-based access before any real deployment.
- Add audit logs, automated tests, pagination, and secure secret management.
- Add integrations with approved log sources or SIEM tools only with explicit authorization.

## Security note

This project is intended for defensive monitoring education. Do not connect it to systems or collect logs without permission. It is a demonstration project, not a production-ready security monitoring system.
