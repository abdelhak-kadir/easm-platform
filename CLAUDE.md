# EASM Platform

**External Attack Surface Management** — Capstone project, ElySec International.
Discovers and continuously maps an organization's internet-facing footprint
(domains, subdomains, IPs, services) using passive and active recon tools,
orchestrated as an iterative discovery loop.

---

## Stack

| Layer | Tech |
|---|---|
| Frontend | Next.js (App Router) + TypeScript |
| Backend API | FastAPI (Python 3.12) |
| Task queue | Celery + Redis |
| Database | PostgreSQL (JSONB for semi-structured data) |
| Infrastructure | Docker Compose (4 services: postgres, redis, backend, celery_worker) |

Backend and worker share the same image (`docker/app.Dockerfile`), built on a
common `easm-base` image with system-level recon deps (`dnsutils`, `openssl`,
`curl`).

---

## Data Model (4 core tables)

```
Asset ──* ScanJob ──* ScanResult ──* Finding
         (spawned_job_id → ScanJob — self-referential chain link)
```

| Model | Purpose |
|---|---|
| `Asset` | A discovered target: `value` + `asset_type` (`domain`/`subdomain`/`ip`). Unique on `(value, asset_type)`. |
| `ScanJob` | One tool run against one asset. Status: `pending → running → completed/failed`. Tracks `spawned_asset_id`/`spawned_job_id` for chained scans. |
| `ScanResult` | Versioned snapshot of a tool's raw JSON output. Re-scanning creates version N+1 — powers future result diffing. |
| `Finding` | Structured facts extracted from a `ScanResult`: `finding_type`, `severity`, JSONB `data`. |

### `finding_type` normalization

Tools that describe "information about a host" all emit `finding_type: "host_info"`
with the **same field names** (`org`, `country`, `hostnames`, `asn`, …). This lets
cross-tool queries and the frontend render findings generically without special-casing
each tool. Adding a tool that reuses existing types needs zero frontend changes;
unregistered types render as raw JSON fallback.

---

## Tool Module Contract

Every recon tool is under `backend/app/tools/<toolname>/` with exactly two files:

```
scan.py   — thin SDK/API wrapper (only file allowed to make network calls)
parse.py  — pure function: dict → list[Finding-ready dicts] (no I/O, no side effects)
```

**`scan.py`** raises one of three typed exceptions (all from `app/tools/base.py`):
- `ToolScanError` — generic failure
- `ToolRateLimitError` — transient, safe to retry
- `ToolNoDataError` — ran fine, target just has nothing (not a failure)

**`parse.py`** is a pure function — trivially unit-testable with canned API responses.

### Registry (`app/tools/registry.py`)

Declarative mapping of `ToolName → ToolSpec(run, parse, asset_types, spawns?, …)`.
`tools_for_asset_type()` answers "which tools apply to this asset?" — the orchestrator
calls it, not the client. Adding a tool = one new registry entry; `app/tasks.py` and
the routers never change.

Chaining fields (all optional): `spawns`, `spawn_asset_type`, `resolve_spawn_value`.
Handled generically in `app/tasks.py::_spawn_chained_scan`.

---

## Tool Inventory

| Tool | Status | Asset Types | Notes |
|---|---|---|---|
| WHOIS | ✅ Complete | Domain, Subdomain | Chains to Shodan via DNS A-record |
| Shodan | ✅ Complete | IP | Chains to WHOIS via rDNS/PTR cache |
| Reverse DNS | ✅ Complete | IP | Internal + chaining support; chains to WHOIS |
| Email Security | ✅ Complete | Domain, Subdomain | SPF/DKIM/DMARC checks |
| theHarvester | 🔧 In Progress | Domain, Subdomain | On branch `tools/theharvester` |
| Nmap | ⬜ Planned | IP | Will need privileged container |
| Censys | ⬜ Planned | IP | |
| HIBP | ⬜ Planned | Email | |

---

## Orchestration: Point-to-Point Chaining (current)

A completed tool can spawn exactly one follow-up tool on a derived asset:
- WHOIS resolves domain → IP → auto-queues Shodan
- Shodan resolves IP → domain (cached rDNS) → auto-queues WHOIS
- Reverse DNS resolves IP → domain → auto-queues WHOIS

### Flow

```
POST /scans/{tool}/{asset_id}
  → ScanJob row created synchronously (PENDING)  ← critical: avoids polling race
  → run_tool_scan.delay(job.id)
  → 202 response with job_id

run_tool_scan(job_id) [Celery worker]
  → status → RUNNING
  → spec.run(asset.value)  [retries on ToolRateLimitError, max 3]
  → persist ScanResult + Findings
  → status → COMPLETED / FAILED
  → _spawn_chained_scan()  [even on "no data" — DNS resolution may still succeed]
```

### Why sync job creation?

If the worker creates the `ScanJob` row, there's a race: frontend has a `task_id` but
`GET /scans/{job_id}` 404s until the worker picks up the task. Creating it in the API
handler first means polling works instantly.

### Future: Wave-based loop

The architecture target is `schedule_round → collect_round → re-trigger` recursively
with a `MAX_ROUNDS` safety cap — generalizing point-to-point chaining into N tools
spawning N follow-ups per round until no new PENDING assets remain.

---

## API Surface

| Endpoint | Purpose |
|---|---|
| `POST /assets` | Create/find asset (type inferred server-side) |
| `GET /assets`, `GET /assets/{id}` | List / fetch |
| `POST /scans/discover/{asset_id}` | Registry-driven: queue all applicable tools |
| `POST /scans/{tool}/{asset_id}` | Single-tool trigger |
| `GET /scans/{job_id}` | Job status + chain metadata |
| `GET /scans/{job_id}/results` | Latest ScanResult + Findings |
| `GET /scans/asset/{asset_id}` | Full job history for one asset |
| `GET /scans`, `GET /scans/stats` | Dashboard feed + aggregates |

⚠️ Route ordering matters: `/scans/discover/…` and `/scans/stats` must be registered
**before** `/scans/{tool}/…` and `/scans/{job_id}` — otherwise FastAPI tries to parse
`"discover"`/`"stats"` as a `ToolName`/`int` and returns 422.

---

## Frontend

- Visual: **console-style dark-terminal** design system (CSS custom properties, IBM
  Plex Sans/Mono, hairline borders, severity-colored left-bar rows, bracket tags).
- Key components: `AssetSearch`, `ScanHistory`, `FindingCard`, `StatsSummary`,
  `SeverityChart`, `FindingsToolbar`.
- `FindingCard` has per-`finding_type` renderers; unregistered types get JSON fallback.
- Live polling on `PENDING`/`RUNNING` jobs via `GET /scans/asset/{id}`.
- `res.ok` must be checked before `setState` — prevents crash on non-2xx responses.
- `.env.local` changes require a dev-server restart (Next.js doesn't hot-reload it).

---

## Development

```bash
# Backend
cd backend && source ../.venv/bin/activate
pytest --cov                # tests with coverage
ruff check .                # lint (line-length 100, py312 target)
black --check --diff .      # format check

# Frontend
cd frontend && npm run dev  # dev server (restart after .env.local changes)

# Full stack
docker compose up -d        # postgres, redis, backend, celery_worker
```

### CI gates (Conventional Commits, branch protection on `main`)
1. Lint (`ruff`)
2. Format (`black`, line-length 100, py312)
3. Tests (`pytest --cov`)
4. Docker build

---

## Key Decisions

| Decision | Why |
|---|---|
| `Base.metadata.create_all()` not Alembic | Schema evolving fast; migration process overhead not yet justified |
| Lazy `get_engine()` via `@lru_cache` | Keeps DB out of import time — pure unit tests don't need a database |
| No per-tool Docker containers yet | Premature until Nmap needs raw-socket isolation |
| `ipaddress.ip_address()` for type inference | Server-side only — never trust client type hints |
| JSONB not separate document store | Queryability of relational + flexibility of unstructured in one DB |

---

## Remaining Work (priority order)

1. **theHarvester** integration (current branch `tools/theharvester`)
2. Nmap, Censys, HIBP — completing the tool suite
3. Full wave-based orchestration (generalize chaining)
4. Result diffing between ScanResult versions
5. Risk scoring / CVE correlation beyond Shodan CVSS passthrough
6. Frontend containerization + frontend test suite
7. Benchmark run against reNgine and EasyEASM
