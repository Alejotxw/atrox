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

## Dashboard de KPIs (HU-019)

Panel superior del tab **Dashboard**, integrado directamente en `src/app/App.tsx` (antes vivía en `src/app/pages/Dashboard.tsx`, eliminado para no duplicar la fila de métricas con datos hardcodeados que existía por separado):

- KPIs con datos reales: hosts descubiertos, puertos/servicios, vulnerabilidades críticas (vía `fetchDashboardKpis` en `lib/dashboardMetrics.ts`)
- Datos desde `GET /api/jobs` + `GET /api/scans/{id}` (HU-010)
- Polling cada 5 s sin recargar la página
- Grid responsive desktop: 1 → 2 → 4 columnas
- La 4ª tarjeta ("Estado del Reporte") es local al flujo de "Iniciar Auditoría Automatizada" (Iniciando/Completado/Error), no proviene del polling de KPIs

Documentación Lighthouse: [`docs/Frontend/HU-019-lighthouse.md`](../../docs/Frontend/HU-019-lighthouse.md)

```bash
npm run test -- dashboardMetrics
```

## Consola en vivo (HU-020)

Componente `src/app/components/ScanConsole/ScanConsole.tsx` en el Dashboard:

- Stream SSE: `GET /api/console/stream` (timestamp, módulo, severidad) — sin demo simulada, todo el contenido proviene de jobs reales.
- Al enviar un job real (`POST /api/jobs`, disparado por **Iniciar Auditoría Automatizada**), la cola (`atrox/queue/service.py`) emite el ciclo de vida: encolado → iniciado → completado/fallido.
- El dispatcher (`atrox/main.py::_dispatch_scan`) enriquece esos eventos con detalle real del resultado: para discovery (Nmap), un resumen de hosts activos y puertos abiertos; para vulnscan (Nuclei), una línea por cada hallazgo `CRITICAL`/`HIGH` con su plantilla y host.
- Al cambiar `auditToken` (nueva auditoría), la consola se limpia visualmente — no dispara ninguna llamada HTTP adicional.
- Auto-scroll configurable (checkbox en el header)
- Reconexión automática si cae el EventSource

```bash
npm run test -- scanConsole
```

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

## Marcado manual de falsos positivos (HU-022)

Dentro de la fila expandida de un hallazgo (HU-021), botón **"Marcar como falso positivo"** → `POST /api/scans/{scan_id}/findings/false-positive` (`markFalsePositive` en `src/app/lib/api.ts`). Al confirmar el marcado, la fila se retira de la tabla localmente (el backend ya la excluye por defecto en HU-010, así que no hace falta refetchear toda la página).

No hay login/autenticación en el frontend todavía: se reutiliza el mismo usuario hardcodeado que ya muestra el sidebar ("Admin SecOps", ver `App.tsx`) como cabecera `X-Atrox-User`, en vez de introducir un flujo de identidad nuevo fuera del alcance de esta HU.

No existe tooling de E2E de navegador en el proyecto (ni Playwright ni Cypress) — el flujo completo (crear escaneo → marcar → exclusión en HU-010 → evento de auditoría HU-008) está cubierto como test de integración a nivel API en el backend (`tests/test_false_positive_e2e_flow.py`), no como E2E de UI. Del lado del frontend, el flujo de click está cubierto por tests de componente con `fetch` mockeado en `FindingsManagementView.test.tsx`.

## Sistema de UI

`src/app/components/ui/` es un set shadcn/ui (Radix + `class-variance-authority` + Tailwind). Antes de HU-021 estaba en el código pero sin sus dependencias instaladas y sin uso real — `App.tsx` usaba Tailwind con colores hex a mano (`#0F172A`, `#7A1C3E`, `#D4AF37`, paleta oscura fija). HU-021 instaló las dependencias faltantes y es la primera vista que usa `components/ui/` de verdad, con los tokens de tema oscuro (`className="dark"` en el contenedor raíz de la vista, ver `src/styles/theme.css`). El resto del dashboard (`App.tsx`) sigue usando su paleta hex propia — son dos sistemas visuales coexistiendo, no unificados en esta tarea.
