# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Atrox is an AI-assisted automated pentesting framework. It has a Python/FastAPI backend for security scanning (Nmap integration) and a React/Vite frontend dashboard that visualizes scan results.

## Repository Structure

- `src/Backend/` — Python FastAPI async API (package: `atrox`)
- `src/Frontend/` — React 19 + Vite 8 + Tailwind CSS 4 dashboard
- `.Github/workflows/` — CI pipelines (note: capital G in `Github`)

The backend and frontend are independent projects with separate dependency management. There is no monorepo tooling linking them.

## Backend Commands

All backend commands run from `src/Backend/`.

```bash
# Activate virtualenv (Windows)
.venv\Scripts\Activate.ps1

# Install (editable + dev deps)
pip install -e ".[dev]"

# Run API server
python -m atrox
# or: atrox-api

# Run unit tests only (no Nmap required)
pytest tests/ -v -m "not integration"

# Run a single test
pytest tests/test_nmap_wrapper.py::test_scan_parses_open_ports_from_mocked_nmap -v

# Run integration tests (requires Nmap installed)
pytest tests/ -v -m integration
```

## Frontend Commands

All frontend commands run from `src/Frontend/`.

```bash
npm install
npm run dev      # Vite dev server
npm run build    # Production build
npm run lint     # ESLint
```

## Architecture

### Backend

- **Entry point**: `atrox/__main__.py` runs uvicorn; `atrox/main.py` has the `create_app()` factory
- **Config**: `atrox/config.py` — `pydantic-settings` with `ATROX_` env prefix (e.g., `ATROX_PORT`, `ATROX_NMAP_PATH`, `ATROX_DEBUG`)
- **API routers**: `atrox/api/health.py` (`/health`) and `atrox/api/discovery.py` (`/api/discovery/scan`)
- **Scanner layer**: `atrox/scanner/` — `NmapWrapper` runs Nmap as an async subprocess, parses XML output. Accepts an injectable `runner` callable for testing without Nmap
- **Validators**: `atrox/scanner/validators.py` — target (IP/FQDN) and port-range validation used by Pydantic models
- **Testing pattern**: Unit tests use a mock `runner` function injected into `NmapWrapper`. API tests use FastAPI `dependency_overrides` to swap `get_nmap_wrapper`. Integration tests are marked with `@pytest.mark.integration` and require Nmap on the system

### Frontend

- React 19 SPA with a single-file dashboard (`src/app/App.tsx`) containing simulated audit flow
- UI components in `src/app/components/ui/` (shadcn/ui pattern)
- Tailwind CSS 4 via `@tailwindcss/vite` plugin (no `tailwind.config.js` — uses CSS-based config)
- No TypeScript config file — Vite handles TSX directly
- Currently the frontend is a static prototype with simulated data; not yet connected to the backend API

## CI

- `backend-ci.yml` — runs on changes to `src/Backend/`, executes unit tests then integration tests (installs Nmap in CI)
- `ci.yml` — Flutter-based pipeline (legacy, from an earlier mobile version)

## Conventions

- Backend code and user-facing strings are in Spanish
- Python >=3.10, uses union syntax (`X | None` not `Optional[X]`)
- Branch naming: `HU/NNN-description` or `HU-NNN` (HU = Historia de Usuario)
- Pytest markers: `integration` for tests requiring external tools (Nmap)
