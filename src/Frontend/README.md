# Atrox Frontend — Dashboard (React 19 + Vite 8 + Tailwind 4)

Dashboard del framework Atrox. El punto de entrada real es `src/main.tsx` → `src/app/App.tsx` (`src/App.jsx` es el scaffold por defecto de Vite, no está montado — ver `CLAUDE.md`).

## Requisitos

- Node.js 18+
- `npm`

## Arranque local

```bash
cd src/Frontend
npm install
npm run dev
```

## Variables de entorno

`VITE_API_BASE_URL` — URL base del backend Atrox (por defecto `http://localhost:8000` si no se define; ver `src/app/lib/api.ts`). No existe archivo `.env` versionado — creá uno local `.env` con:

```
VITE_API_BASE_URL=http://localhost:8000
```

## Comandos

```bash
npm run dev       # servidor de desarrollo
npm run build     # build de producción
npm run lint      # eslint (solo *.js/*.jsx — ver nota abajo)
npm run test      # tests de componente (vitest, una corrida)
npm run test:watch  # vitest en modo watch
```

**Nota:** `eslint.config.js` solo lintea `**/*.{js,jsx}`; los archivos `.ts`/`.tsx` (incluyendo `App.tsx` y todo `components/ui/`) no pasan por lint hoy. Tampoco hay `typescript` instalado ni `tsconfig.json`, así que los tipos en archivos `.ts`/`.tsx` no se verifican en build (`vite build` no corre `tsc`). Extender el lint/type-check a TS es trabajo pendiente, no cubierto por esta tarea.

## Gestión de Hallazgos (HU-021)

Tab **"Gestión de Hallazgos"** en el sidebar (`src/app/components/findings/FindingsManagementView.tsx`). Dado un `scan_id` (obtenido de `POST /api/scans`, HU-009), integra tres endpoints del backend:

- `GET /api/scans/{scan_id}` (HU-010) — lista paginada de hallazgos, filtro server-side por severidad.
- `POST /api/ai/scoring/score` (HU-016) — score de confianza 0-100 y `probable_fp` por hallazgo (un request por hallazgo de la página actual; no existe endpoint batch en el backend).
- `POST /api/ai/vectors/analyze` (HU-014) — vector de ataque correlacionado por hallazgo; se llama en lotes de 10 (`VECTORS_BATCH_SIZE` en `src/app/lib/findingsView.ts`) porque el backend trunca a `MAX_BATCH_SIZE=10` por request.

Filtro de severidad → server-side (refetch a HU-010). Filtros de confianza mínima y falso-positivo → client-side, sobre la página ya cargada (el backend no expone un filtro de score). Fila expandible con evidencia (`extracted_results`, descripción, tags, referencias) más la explicación del score y la cadena del vector correlacionado.

Lógica de merge/filtro separada en `src/app/lib/findingsView.ts` (funciones puras, sin DOM) para poder testearla directamente — ver `findingsView.test.ts` y `FindingsManagementView.test.tsx`.

```bash
npm run test -- findingsView FindingsManagementView
```

## Sistema de UI

`src/app/components/ui/` es un set shadcn/ui (Radix + `class-variance-authority` + Tailwind). Antes de HU-021 estaba en el código pero sin sus dependencias instaladas y sin uso real — `App.tsx` usaba Tailwind con colores hex a mano (`#0F172A`, `#7A1C3E`, `#D4AF37`, paleta oscura fija). HU-021 instaló las dependencias faltantes y es la primera vista que usa `components/ui/` de verdad, con los tokens de tema oscuro (`className="dark"` en el contenedor raíz de la vista, ver `src/styles/theme.css`). El resto del dashboard (`App.tsx`) sigue usando su paleta hex propia — son dos sistemas visuales coexistiendo, no unificados en esta tarea.
