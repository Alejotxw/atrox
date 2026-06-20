# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Atrox** is an AI-assisted automated pentesting framework. It orchestrates security tools (Nmap, Nuclei, SQLMap, Metasploit) with a local Ollama/Llama 3 engine for intelligent vulnerability correlation and mitigation recommendations. Results are stored in SQLite.

The current frontend is a dashboard simulation/prototype — UI modules show simulated audit flows, not live tool integration yet.

## Repository Structure

```
src/Frontend/          ← React + Vite frontend (all dev commands run from here)
docs/                  ← Project documentation (vision, SRS, interviews, architecture diagrams)
.Github/workflows/     ← CI pipeline (currently configured for Flutter, NOT the React frontend)
```

## Development Commands

All commands must be run from `src/Frontend/`:

```bash
cd src/Frontend
npm install        # install dependencies
npm run dev        # start Vite dev server (HMR)
npm run build      # production build
npm run lint       # ESLint
npm run preview    # preview production build
```

## Tech Stack

- **React 19** with TypeScript (`.tsx` files)
- **Vite 8** with `@vitejs/plugin-react` (Oxc-based)
- **Tailwind CSS v4** via `@tailwindcss/vite` plugin (no `tailwind.config` file — uses CSS-first configuration)
- **shadcn/ui** components in `src/app/components/ui/` (uses `clsx` + `tailwind-merge` via `cn()` utility)
- **Lucide React** for icons
- **tw-animate-css** for animations

## Architecture

- **Entry point**: `src/main.tsx` → mounts `src/app/App.tsx`
- **Single-file app**: The entire dashboard UI lives in `src/app/App.tsx` as one component with inline sub-components (`NavItem`, `MetricCard`, `TableRow`, view components like `ReconView`, `ScanView`, etc.)
- **UI primitives**: `src/app/components/ui/` contains shadcn/ui components — do NOT edit these directly unless customizing the design system
- **Custom components**: `src/app/components/figma/` holds components exported from design tools (e.g., `ImageWithFallback`)
- **Styles**: CSS is layered in `src/styles/` — `index.css` imports `fonts.css`, `tailwind.css`, and `theme.css`. The theme uses CSS custom properties with light/dark mode support via oklch colors

## Key Conventions

- The UI language is **Spanish** — component labels, nav items, log messages, and vulnerability descriptions are all in Spanish
- Brand colors: primary accent `#7A1C3E` (burgundy), gold `#D4AF37`, dark background `#0F172A`
- The `cn()` utility at `src/app/components/ui/utils.ts` is the standard way to merge Tailwind classes
- Tailwind v4 CSS-first config: source scanning is declared in `src/styles/tailwind.css`, NOT in a JS config file

## CI/CD Note

The `.Github/workflows/ci.yml` is configured for a Flutter project (not the React frontend). It will not work for the current codebase without being rewritten for Node.js/Vite.
