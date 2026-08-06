# HU-019 — Dashboard web de métricas de seguridad (Lighthouse)

**Historia:** HU-019  
**Criterio RNF-006:** render inicial de métricas en `< 2 s` (conexión estándar)  
**Viewport DoD:** desktop (≥ 1280px)  
**Fecha de medición:** 2026-08-02

---

## Cómo medir (Lighthouse básico)

Con el frontend y backend corriendo:

```bash
# Terminal 1 — backend
cd src/Backend
python -m atrox

# Terminal 2 — frontend
cd src/Frontend
npm run dev
```

Medición Lighthouse (desktop):

```bash
npx --yes lighthouse http://localhost:5173 \
  --only-categories=performance \
  --preset=desktop \
  --chrome-flags="--headless" \
  --output=json \
  --output-path=./lighthouse-hu019.json \
  --quiet
```

O con UI:

```bash
npx --yes lighthouse http://localhost:5173 --view --preset=desktop
```

---

## Qué se valida para HU-019

| Criterio | Evidencia |
| :--- | :--- |
| Render inicial &lt; 2 s | Shell + cards KPI pintan de inmediato; fetch HU-010 en background |
| Métricas consumen HU-010 | `getScanDetail` + `listJobs` en `dashboardMetrics.ts` |
| Actualización sin recarga | `setInterval` cada 5 s (sin `location.reload`) |
| Responsive desktop | `grid-cols-1 md:grid-cols-2 xl:grid-cols-4` |

---

## Resultado esperado / checklist manual

- [ ] Abrir Dashboard en viewport ≥ 1280px: 4 KPIs en una fila
- [ ] Con backend caído: mensaje de error, UI no se bloquea
- [ ] Con jobs `done` de discovery/vulnscan: KPIs &gt; 0
- [ ] Esperar 5 s: “última actualización” cambia sin F5
- [ ] Lighthouse Performance: LCP / FCP del shell &lt; 2 s en local

---

## Archivos

- `src/Frontend/src/app/pages/Dashboard.tsx` — panel de KPIs
- `src/Frontend/src/app/lib/dashboardMetrics.ts` — agregación + fetch HU-010
- `src/Frontend/src/app/lib/dashboardMetrics.test.ts` — tests unitarios
