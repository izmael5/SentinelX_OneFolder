# SentinelX Security Operations

SentinelX is a mobile-first defensive security operations dashboard for websites and networks that you own or are explicitly authorized to assess.

## Included in this first build

- Authorized target registry with scope notes
- Safe, non-destructive website posture checks
- Findings triage and explainable risk scoring
- Live dashboard events over WebSockets
- Optional AI research summaries through the managed runtime API
- MySQL persistence, Dockerfile, Docker Compose, and YAML configuration

## Safety boundary

SentinelX intentionally does not execute unrestricted exploits, brute-force credentials, deliver payloads, create persistence, or scan arbitrary targets. Assessment jobs only run for enabled records in the target registry and are rate-limited. Any future intrusive testing must be separately approved and restricted to a designated test scope.

## Local run with Docker

```bash
cp .env.example .env
docker compose up --build
```

Open `http://localhost:3000`.

## Local run without Docker

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL='mysql+pymysql://sentinelx:sentinelx@127.0.0.1:3306/sentinelx'
uvicorn backend.app.main:app --host 0.0.0.0 --port 3000 --reload
```

## Runtime configuration

- `DATABASE_URL`: MySQL-compatible DSN
- `MANUS_API_URL` and `MANUS_API_KEY`: optional managed AI runtime adapter
- `MANUS_PROJECT_ID`, `MANUS_OAUTH_PORTAL_URL`, `MANUS_OAUTH_API_URL`, `MANUS_JWT_SECRET`: optional managed account login integration
- `PORT`: listener port, default `3000`

## API highlights

- `GET /api/health`
- `GET /api/overview`
- `GET/POST /api/targets`
- `GET /api/findings`
- `POST /api/scan-jobs`
- `POST /api/research/brief`
- `WS /api/ws/events`
"# SentinelX_OneFolder" 
