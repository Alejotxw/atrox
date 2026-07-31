# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Atrox — an AI-assisted automated pentesting framework. A Python/FastAPI backend drives asset discovery (Nmap) and vulnerability scanning (Nuclei), with a LangGraph-based agent that analyzes findings and proposes attack vectors. A React/Vite frontend provides the operator dashboard. Requirements are tracked as RF-* (functional) / RNF-* (non-functional) in `docs/SRS.md`, with architecture decisions in `docs/ADR/`.

This is a student/academic project (per `docs/ADR/*` and `.Github/CODEOWNERS`); work is tracked as `HU-NNN` (Historia de Usuario) user stories.

## Repo layout

```
src/Backend/   FastAPI backend (Python) — the real backend
src/Frontend/  React 19 + Vite 8 + Tailwind 4 dashboard
src/openspec/  SDD artifacts (spec-driven-development changes, config)
docs/          SRS, ADRs, AI orchestration diagrams
```

Two things look like backend/frontend code but are not:
- `src/Backend/package.json` (express/cors) has no server file behind it — vestigial, unused. Ignore it; `atrox/` is the real backend.
- `src/Frontend/src/App.jsx` + `main.tsx`'s default Vite scaffold — **not** the mounted app. The actual entry point is `src/Frontend/src/main.tsx` → `src/app/App.tsx` (one large file holding the whole dashboard), with shared UI primitives in `src/app/components/ui/`.

**`.Github/` is capitalized**, not `.github/`. Because GitHub Actions only discovers workflows under the exact lowercase path, the workflows in `.Github/workflows/*.yml` are not actually triggered on GitHub — including `ci.yml`, which is a leftover Flutter pipeline unrelated to this codebase (no Flutter files exist here) and should not be treated as real CI. `backend-ci.yml` describes the intended backend CI job but has the same casing problem.

## Commands

### Backend (`src/Backend/`)

```bash
cd src/Backend
python -m venv .venv && .\.venv\Scripts\Activate.ps1   # Windows
pip install -e ".[dev]"

uvicorn atrox.main:app --host 0.0.0.0 --port 8000 --reload   # run dev server
# or: atrox-api   /   python -m atrox

pytest tests/ -v -m "not integration"     # unit tests (default)
pytest tests/test_encryption.py -v        # single file
pytest tests/ -v -m integration           # integration tests (needs Nmap/Nuclei on PATH)
```

No linter/formatter/type-checker is configured for the backend (per `src/openspec/config.yaml`).

### Frontend (`src/Frontend/`)

```bash
cd src/Frontend
npm run dev
npm run build
npm run lint
```

No frontend test runner is configured.

## Architecture

**Concurrency model (ADR-001):** the backend is Python/FastAPI on `asyncio` for I/O-bound work (network scans); CPU-bound parsing is delegated to a `ProcessPoolExecutor` to escape the GIL. Don't introduce blocking synchronous calls on the async request path.

**Job queue (`atrox/queue/service.py`):** `JobQueue` wraps an `asyncio.Queue` + `asyncio.Semaphore(max_concurrent)`; a fixed pool of worker coroutines (`_worker`) pulls job IDs and dispatches to a single injected `scanner` callable. The dispatcher that maps `JobType` → concrete wrapper (Nmap/Nuclei) lives in `atrox/main.py::_dispatch_scan`, not in the queue itself — the queue is scan-type-agnostic.

**AI orchestration (ADR-002, `atrox/ai/graph/`):** a LangGraph `StateGraph` cycles through `analyze → propose → execute → evaluate`, looping back to `analyze` until a `PentestDecider` signals stop or `max_steps` is hit (`graph.py::_route_after_evaluate`). `PentestDecider` is an interface with `HeuristicDecider` (rule-based, default) and `MockDecider` (deterministic, for tests) implementations — swap the decider to change reasoning strategy without touching graph wiring. State is checkpointed via `MemorySaver` keyed by `thread_id`, so a session's graph state can be resumed via `get_persisted_state`.

**Vector analysis (`atrox/ai/agents/vectors/`):** `correlator.py` correlates raw Nuclei findings into candidate attack chains; `analyzer.py` is the orchestration entry point exposed at `POST /api/ai/vectors/analyze`.

**Encryption at rest (ADR-003):** `atrox/security/encryption.py` implements AES-256-GCM via the `cryptography` package. The master key comes only from `ATROX_ENCRYPTION_MASTER_KEY` (env) — never hardcode or commit it; `atrox/security/deps.py::get_encryption_service_from_settings` raises `EncryptionKeyError` if it's unset. `sensitive_fields.py` defines which fields (findings' description/evidence/poc/raw_output, credentials' password/secret/token/private_key, reports' content/summary/technical_details/body) get encrypted before persistence to `data/encrypted/*.jsonl`, and decrypted only on authorized read (e.g. `GET /api/jobs/{id}`).

**Audit log (ADR-003):** `atrox/security/audit_signer.py` + `audit_service.py` implement an append-only log signed with HMAC-SHA256 (key from `ATROX_AUDIT_SIGNING_KEY`), queryable via `GET /api/audit/logs` and integrity-checked via `GET /api/audit/integrity`. Every `POST /api/jobs` submission is auto-logged as `scan.submitted`. Audit logging is entirely disabled (`app.state.audit_log = None`) when the signing key isn't configured — see `atrox/main.py::lifespan`.

**API routers (`atrox/api/`):** each module owns one router mounted in `atrox/main.py::create_app` — `health`, `discovery` (Nmap), `vulnscan` (Nuclei), `jobs` (queue submission/status), `audit`, `vectors` (AI attack-vector analysis).

## Conventions

- User-facing strings and code comments are written in **Spanish** (see any existing module/README) — match this when touching backend code.
- Prefer PEP 604 unions (`X | None`) over `Optional[X]`.
- This repo runs under **strict TDD** (`src/openspec/config.yaml: strict_tdd: true`) when doing SDD-flow work: write/adjust the failing test before implementation.
- Settings are centralized in `atrox/config.py::Settings` (pydantic-settings, `ATROX_` env prefix) — add new config there rather than reading `os.environ` directly.
- New security-sensitive fields must be registered in `atrox/security/sensitive_fields.py` to actually get encrypted; adding a field to a Pydantic model alone does not encrypt it.
