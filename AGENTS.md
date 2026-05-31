# AGENTS.md — atrox / AetherPentest

## What this is

**atrox** is the root repo; **`aetherpentest/`** is the actual project — a Python pentesting framework with a React dashboard. The root `README.md` is a stub; all docs live in `aetherpentest/README.md`.

## Architecture

```
atrox/
├── aetherpentest/          # Python package (framework)
│   ├── core/               # orchestrator, agent, database, reporter, config
│   ├── modules/            # reconnaissance, scanning, enumeration, vulnerability, exploitation
│   ├── tools/              # nmap, subfinder, nikto, nuclei, sqlmap, metasploit wrappers
│   ├── cli/cli.py          # Typer CLI (entry: main_entry)
│   ├── backend/api.py      # FastAPI server (port 8000)
│   ├── config/settings.yaml
│   └── frontend/           # React + Vite + TailwindCSS v4
│       └── src/
│           ├── pages/      # 7 route pages
│           └── lib/api.ts  # fetch-based API client
└── .atl/                   # skill-registry (auto-managed, do not edit)
```

Two separate runtime environments:
- **Python 3.11+** — framework + CLI + API backend
- **Node** — React frontend (Vite + TypeScript 6.0 + React 19)

## Entrypoints

| What | Command | Notes |
|------|---------|-------|
| CLI | `python -m aetherpentest.main <command>` | or `aetherpentest` if `pip install -e .` |
| API | `python -m aetherpentest.backend.api` | FastAPI on `:8000`, docs at `/docs` |
| Frontend dev | `npm run dev` (from `frontend/`) | Vite on `:5173`, proxies `/api` → `:8000` |
| Frontend build | `npm run build` | `tsc -b && vite build`, output to `dist/` |

## CLI commands

All via `aetherpentest <command>` or `python -m aetherpentest.main <command>`:

- `run <target>` — pentest workflow (flags: `-w` workflow, `-y` auto-confirm, `--no-agent`)
- `target list|add|show|delete` — manage targets
- `sessions [--id N]` — session history
- `report <session_id>` — PDF report
- `doctor` — check dependencies (ext tools + Python pkgs + Ollama)
- `agent status|clear|analyze` — AI agent management
- `ask "question"` — chat with AI
- `stats` — framework statistics

Workflows: `full`, `recon_only`, `scan_only`, `vuln_only`, `web_app`, `infrastructure`, `api`, `quick`

## Configuration

Loading order: `settings.yaml` → env vars (prefix `AETHER_`).

Key vars: `AETHER_MODEL`, `AETHER_OLLAMA_HOST`, `AETHER_LOG_LEVEL`.

Config file: `aetherpentest/config/settings.yaml` — model, tool paths, security, logging.

## Notable facts for an agent

- **No tests exist anywhere in the repo.** Zero. No pytest config, no test dirs, no CI.
- **No linter/formatter config** (no `ruff`, `black`, `pylint`, or `.pre-commit-config.yaml`).
- **No CI/CD** (no `.github/`, no Dockerfile, no Makefile).
- **Single commit** (`d164de3` — "Initial commit") on `main`, remote: `Alejotxw/atrox.git`.
- Frontend lint: `npm run lint` (ESLint) from `frontend/`.
- Python deps: `pip install -r aetherpentest/requirements.txt`.
- No `opencode.json` in the repo.
- Python imports use `aetherpentest.` prefix (package name).
- Logs go to `aetherpentest/data/aetherpentest_YYYYMMDD.log`.
- Reports go to `aetherpentest/reports/`.
- AI agent requires **Ollama** running locally with `llama3.1` (or `mistral`) model pulled.
- External tools required for full functionality: nmap, subfinder, nikto, nuclei, sqlmap, metasploit-framework.
