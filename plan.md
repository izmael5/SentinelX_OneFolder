# SentinelX Security Operations — Implementation Plan

## Product scope
SentinelX is a mobile-first defensive security operations web app for websites and networks that the operator owns or is explicitly authorized to assess. It combines target inventory, safe non-destructive assessment, findings triage, research assistance, and a real-time SOC-style view.

The product deliberately does **not** provide unrestricted exploit execution or autonomous actions against arbitrary systems. Every assessment starts from an explicit target record, records authorization metadata, enforces an allowlist, applies rate limits, defaults to safe checks, and writes an audit event. Intrusive actions, if added later, must be separately approved and isolated to a designated test scope.

## Architecture

- **Frontend:** responsive HTML/CSS/vanilla JavaScript served from FastAPI. A bottom navigation pattern becomes a left rail on wide screens. WebSocket events update the dashboard without a refresh.
- **API:** Python FastAPI service with typed Pydantic request models, SQLAlchemy persistence, background scan jobs, and WebSocket event fanout.
- **Database:** MySQL-compatible schema for targets, scan jobs, findings, events, and operator notes. The platform-managed `DATABASE_URL` is used in managed environments; Docker Compose supplies MySQL 8.4 locally.
- **Assessment worker:** safe HTTP/TLS posture checks only: connectivity, response status, redirect behavior, security headers, TLS metadata where available, and exposure of server banners. No payload delivery, credential guessing, persistence, destructive requests, or exploit execution.
- **Risk/ML layer:** deterministic explainable scoring for the first release, with an optional platform LLM adapter for research summaries and remediation suggestions. Model output is advisory and never triggers an action by itself.
- **Deployment:** Dockerfile for the app, Docker Compose for the app + MySQL, YAML configuration, health endpoint, and runtime-aware `PORT` handling.

## Project structure

```text
backend/
  app/
    main.py          FastAPI app, static serving, lifespan
    config.py        environment settings and safe defaults
    db.py            SQLAlchemy engine/session setup
    models.py        persistent domain models
    schemas.py       API input/output models
    security.py      authorization scope and audit helpers
    scanner.py       safe URL posture assessment
    ml.py            explainable risk scoring
    research.py      optional AI research adapter with safe prompt boundaries
    routes.py        API routes and WebSocket event manager
  migrations/        additive MySQL schema
frontend/
  index.html         mobile-first application shell
  app.js             dashboard state, charts, target and scan interactions
  styles.css         dark operations-console design system
public/
  manus-routes.json  route manifest required by the platform
Dockerfile            production container
Docker Compose.yml    local app + MySQL environment
plan.md              implementation and design decisions
TODO.md              outcome-based delivery criteria
```

## Design direction

- **Design movement:** quiet cybernetic operations console — dense enough for analysts, calm enough for sustained incident work.
- **Core principles:** evidence before alarm; high signal over decoration; scope is visible at every action; mobile workflows remain one-thumb usable.
- **Color philosophy:** near-black ink and slate surfaces reduce glare; a mint signature color marks trusted telemetry; amber and coral are reserved for attention and risk, never for decoration.
- **Layout paradigm:** a command rail plus flowing evidence stream rather than a centered card grid. The overview leads with one status sentence, then a live event rail, then focused evidence panels.
- **Signature elements:** mint “signal thread” connecting events; compact severity pills; target-scope chips that always expose the authorized boundary.
- **Interaction philosophy:** every state change is explainable. Scan buttons show the selected target and check family; empty states tell the operator what authorization or configuration is missing.
- **Animation:** short 160–220ms fades and slide-ins for new telemetry; no perpetual motion; status pulse is limited to live connection state.
- **Typography:** IBM Plex Sans for UI text, IBM Plex Mono for hostnames, timestamps, IDs, and telemetry. Use strong numeric hierarchy for counts.
- **Brand essence:** “A clear operating picture for the systems you are trusted to defend.” Personality: precise, vigilant, grounded.
- **Brand voice:** concise and evidence-led. Example lines: “Scope first. Signal second.” and “This finding is actionable because the evidence is reproducible.”
- **Wordmark/logo:** a compact `S/` signal mark: two offset mint strokes forming a shield-like aperture, paired with the SentinelX wordmark.
- **Signature brand color:** Signal Mint `#49E3B2`.

## Implementation phases

1. Scaffold the API, schema, safe scanner, frontend shell, Docker assets, and route manifest.
2. Add target registration, scope enforcement, background scans, risk scoring, findings triage, and WebSocket events.
3. Add optional AI-assisted research summaries using the platform runtime API, with no action execution from model output.
4. Validate with Python compile checks, route/health checks, API smoke tests, and diagnostics; then save a checkpoint.
