# Mapeo de Secciones Frontend: Escaneo, Validación y Gestión de Hallazgos

**Fecha de búsqueda:** 2026-08-11  
**Ruta explorada:** `src/Frontend/`  
**Términos buscados:** "Escaneo", "Validación", "Gestión de Hallazgos", "Hallazgos"

---

## 📍 RESUMEN EJECUTIVO

Las tres secciones están implementadas como **pestañas dinámicas en un componente principal (App.tsx)**, con un sistema de navegación lateral (sidebar) que controla el `activeTab` mediante clicks en elementos `NavItem`.

| Sección | Archivo | Línea NavItem | Línea Renderizado | Componente | Icono |
|---------|---------|---------------|-------------------|-----------|-------|
| **Escaneo** | App.tsx | 591 | 1147 | `<ScanView>` | `<ScanLine />` |
| **Validación** | App.tsx | 592 | 1150 | `<MetasploitView>` | `<ShieldCheck />` |
| **Gestión de Hallazgos** | App.tsx | 593 | 1151 | `<FindingsManagementView>` | `<ListFilter />` |

---

## 🎯 1. ESCANEO (Nuclei/SQLMap)

### 📌 Ubicación Exacta

**Definición del NavItem:**
- **Archivo:** [src/Frontend/src/app/App.tsx](src/Frontend/src/app/App.tsx#L591)
- **Línea:** 591
- **Label:** `"Escaneo"`
- **Tab ID:** `"Escaneo (Nuclei/SQLMap)"`

```tsx
<NavItem 
  icon={<ScanLine />} 
  label="Escaneo" 
  active={activeTab === 'Escaneo (Nuclei/SQLMap)'} 
  onClick={() => selectTab('Escaneo (Nuclei/SQLMap)')} 
/>
```

**Renderizado del Contenido:**
- **Archivo:** [src/Frontend/src/app/App.tsx](src/Frontend/src/app/App.tsx#L1147)
- **Línea:** 1147
- **Componente:** `<ScanView />`

```tsx
{activeTab === 'Escaneo (Nuclei/SQLMap)' && (
  <ScanView targetUrl={targetUrl} findings={findings} isAuditing={isAuditing} reportStatus={reportStatus} />
)}
```

### 📝 Definición del Componente `ScanView`

- **Archivo:** [src/Frontend/src/app/App.tsx](src/Frontend/src/app/App.tsx#L1364)
- **Línea definición:** 1364
- **Tipo:** Componente React funcional (const arrow function)
- **Props:**
  - `targetUrl: string` — IP/dominio del objetivo
  - `findings: FindingRow[]` — Array de hallazgos encontrados
  - `isAuditing: boolean` — Estado si la auditoría está en curso
  - `reportStatus: string` — Estado del reporte ("Generando", etc.)

**Contenido:** 
- Muestra **contador de hallazgos por severidad** (Crítico, Alto, Medio, Bajo)
- Agrupa hallazgos en tarjetas de severidad
- Barra de progreso cuando `isAuditing === true`
- Plantillas de vulnerabilidad de Nuclei sobre el objetivo

### 🔗 Relaciones y Referencias

- **Importa datos de:** `findings` (estado global en App.tsx)
- **Actualiza:** Nada (read-only)
- **Usada por:** Tab "Escaneo (Nuclei/SQLMap)" en el switch de pestañas (línea 1147)
- **Llamadas relacionadas:**
  - [Línea 1392](src/Frontend/src/app/App.tsx#L1392): Genera título "Resultados de Escaneo (Nuclei)"
  - Líneas 400-467: Manejo de errores de escaneo de Nuclei

---

## 🛡️ 2. VALIDACIÓN (Metasploit)

### 📌 Ubicación Exacta

**Definición del NavItem:**
- **Archivo:** [src/Frontend/src/app/App.tsx](src/Frontend/src/app/App.tsx#L592)
- **Línea:** 592
- **Label:** `"Validación"`
- **Tab ID:** `"Validación (Metasploit)"`

```tsx
<NavItem 
  icon={<ShieldCheck />} 
  label="Validación" 
  active={activeTab === 'Validación (Metasploit)'} 
  onClick={() => selectTab('Validación (Metasploit)')} 
/>
```

**Renderizado del Contenido:**
- **Archivo:** [src/Frontend/src/app/App.tsx](src/Frontend/src/app/App.tsx#L1150)
- **Línea:** 1150
- **Componente:** `<MetasploitView />`

```tsx
{activeTab === 'Validación (Metasploit)' && <MetasploitView targetUrl={targetUrl} />}
```

### 📝 Definición del Componente `MetasploitView`

- **Archivo:** [src/Frontend/src/app/App.tsx](src/Frontend/src/app/App.tsx#L1428)
- **Línea definición:** 1428
- **Tipo:** Componente React funcional (const arrow function)
- **Props:**
  - `targetUrl: string` — IP/dominio del objetivo

**Contenido:**
- Grid de 3 columnas (lg:col-span-3)
- Sesiones activas de Meterpreter
- Status de conexión
- Información de host comprometido (UID, OS)
- Altura fija: `lg:h-[500px]`

### 🔗 Relaciones y Referencias

- **Importa datos de:** `targetUrl` (estado global)
- **Actualiza:** Nada (read-only, UI estática)
- **Usada por:** Tab "Validación (Metasploit)" en el switch de pestañas (línea 1150)
- **Referencias de Validación:**
  - [Línea 592](src/Frontend/src/app/App.tsx#L592): NavItem
  - [Línea 176 (AuditTaskMarker.tsx)](src/Frontend/src/app/components/audit/AuditTaskMarker.tsx#L176): Mención de "Escaneo de fallos" (prerequisito)

---

## 📊 3. GESTIÓN DE HALLAZGOS

### 📌 Ubicación Exacta

**Definición del NavItem:**
- **Archivo:** [src/Frontend/src/app/App.tsx](src/Frontend/src/app/App.tsx#L593)
- **Línea:** 593
- **Label:** `"Gestión de Hallazgos"`
- **Tab ID:** `"Gestión de Hallazgos"`

```tsx
<NavItem 
  icon={<ListFilter />} 
  label="Gestión de Hallazgos" 
  active={activeTab === 'Gestión de Hallazgos'} 
  onClick={() => selectTab('Gestión de Hallazgos')} 
/>
```

**Renderizado del Contenido:**
- **Archivo:** [src/Frontend/src/app/App.tsx](src/Frontend/src/app/App.tsx#L1151)
- **Línea:** 1151
- **Componente:** `<FindingsManagementView />`

```tsx
{activeTab === 'Gestión de Hallazgos' && <FindingsManagementView />}
```

### 📝 Definición del Componente `FindingsManagementView`

- **Archivo:** [src/Frontend/src/app/components/findings/FindingsManagementView.tsx](src/Frontend/src/app/components/findings/FindingsManagementView.tsx)
- **Línea importación (App.tsx):** 34
- **Tipo:** Componente React funcional (export default)
- **Props:** Ninguno (sin props)

**Estructura del archivo:**
```
FindingsManagementView.tsx (200+ líneas)
├── Imports
│   ├── React hooks (useEffect, useMemo, useState)
│   ├── Lucide icons (AlertTriangle, ChevronDown, etc.)
│   ├── API: getScanDetail, markFalsePositive, scoreFinding, analyzeVectors
│   ├── Tipos: ApiError, AttackVector, ConfidenceScoreResult, ScanDetailResponse
│   └── UI primitives: Badge, Button, Table, Select
├── Constants
│   ├── SEVERITY_OPTIONS (Crítica, Alta, Media, Baja, Informativa)
│   ├── CONFIDENCE_OPTIONS (Score ≥ 0, 25, 50, 75)
│   └── FP_OPTIONS (Todos, Solo válidos, Probables falsos positivos)
├── Estado local
│   ├── scanIdInput / scanId (entrada manual del ID de escaneo)
│   ├── severityFilter (filtro por severidad)
│   ├── minScore (filtro de confianza mínima)
│   ├── fpFilter (filtro de falso positivo)
│   ├── page (número de página)
│   ├── scanDetail (respuesta de API)
│   ├── scores (resultados de confianza de IA)
│   ├── vectors (vectores de ataque correlacionados)
│   └── expandedIds (IDs de filas expandidas)
└── Handlers
    ├── handleLoadScan() — Carga scan desde ID manual
    ├── handleFetchVectors() — Correlaciona hallazgos en lotes de 10
    ├── handleMarkFalsePositive() — Marca hallazgo como falso positivo
    └── Renderizado con tabla filtrada
```

**Funcionalidades principales:**
1. **Cargar escaneo por ID:** Input manual + botón "Cargar hallazgos"
2. **Filtros:**
   - Por severidad (Crítica, Alta, Media, Baja, Informativa)
   - Por score de confianza (IA, HU-016)
   - Por estado de falso positivo (HU-010)
3. **Tabla de hallazgos:**
   - ID, Vulnerabilidad, Vector, Criticidad, Estado
   - Rows expandibles para mostrar detalles
4. **Análisis correlacionado:**
   - Llama `analyzeVectors()` en lotes de 10 hallazgos
   - Muestra score de confianza (IA) y vector de ataque propuesto

### 📝 Archivo de Lógica Pura: `findingsView.ts`

- **Archivo:** [src/Frontend/src/app/lib/findingsView.ts](src/Frontend/src/app/lib/findingsView.ts#L1-L50)
- **Línea definición:** Línea 2
- **Propósito:** Lógica pura (sin React) para:
  - Combinar hallazgos, scores y vectores en filas de tabla
  - Filtrar por confianza y falso positivo
  - Priorizar hallazgos por severidad para análisis IA

**Funciones clave:**
- `prioritizeFindingsForAi(findings, limit = 10)` — Ordena por criticidad, toma max 10
- `chunk(items, size)` — Agrupa en lotes (usado para POST /api/ai/vectors/analyze)
- `filterRows(rows, filters)` — Aplica filtros de severidad/confianza/falso positivo
- `buildFindingRows(findings, scores, vectors)` — Combina datos en filas para tabla

### 🔗 Relaciones y Referencias

**Importado por:**
- [App.tsx línea 34](src/Frontend/src/app/App.tsx#L34): `import FindingsManagementView from './components/findings/FindingsManagementView'`

**Llamadas API (desde FindingsManagementView):**
- `GET /api/jobs/{scanId}` via `getScanDetail(scanId)` — Obtiene hallazgos (HU-010)
- `POST /api/ai/vectors/analyze` via `analyzeVectors(findings)` — Correlaciona vectores (HU-014)
- `POST /api/ai/findings/score` via `scoreFinding(findingId)` — Score de confianza (HU-016)
- `POST /api/findings/{findingId}/false-positive` via `markFalsePositive(findingId)` — Marca FP (HU-010)

**Test asociado:**
- [src/Frontend/src/app/components/findings/FindingsManagementView.test.tsx](src/Frontend/src/app/components/findings/FindingsManagementView.test.tsx)
  - Línea 135: Test de input de ID de escaneo
  - Línea 151: Test de validación "Ingresá un ID de escaneo"
  - Línea 205: Test de error 404 "Escaneo no encontrado"

---

## 🗂️ ESTRUCTURA JERÁRQUICA COMPLETA

```
App.tsx (1700+ líneas)
│
├─ Sidebar (líneas 585-610)
│  ├─ NavItem "Dashboard" 
│  ├─ NavItem "Reconocimiento (Nmap)"
│  ├─ NavItem "Escaneo (Nuclei/SQLMap)" ⭐
│  │  └─ label: "Escaneo"
│  │  └─ icon: ScanLine
│  ├─ NavItem "Validación (Metasploit)" ⭐
│  │  └─ label: "Validación"
│  │  └─ icon: ShieldCheck
│  ├─ NavItem "Gestión de Hallazgos" ⭐
│  │  └─ label: "Gestión de Hallazgos"
│  │  └─ icon: ListFilter
│  ├─ NavItem "Motor IA"
│  ├─ NavItem "Historial de Trabajos"
│  └─ NavItem "Administración" (si isSuperAdmin)
│
├─ Main Content Area (líneas 1140-1155)
│  ├─ Dashboard view (líneas 915-1138)
│  ├─ Reconocimiento (Nmap) view (línea 1145) ➜ <ReconView />
│  ├─ Escaneo (Nuclei/SQLMap) view (línea 1147) ➜ <ScanView /> ⭐
│  │  └─ Componente definido en línea 1364
│  ├─ Validación (Metasploit) view (línea 1150) ➜ <MetasploitView /> ⭐
│  │  └─ Componente definido en línea 1428
│  ├─ Gestión de Hallazgos view (línea 1151) ➜ <FindingsManagementView /> ⭐
│  │  └─ Componente importado de ./components/findings/FindingsManagementView
│  │  └─ Archivo: FindingsManagementView.tsx (200+ líneas)
│  ├─ Motor Ollama IA view (línea 1152) ➜ <OllamaView />
│  ├─ Historial de Trabajos view (línea 1153) ➜ <HistoryView />
│  └─ Administración view (línea 1154) ➜ <AdminPanel />
│
└─ Componentes auxiliares
   ├─ ScanView (línea 1364)
   ├─ MetasploitView (línea 1428)
   ├─ ReconView (línea 1259)
   ├─ OllamaView (línea 1488)
   ├─ HistoryView (línea 1648)
   └─ FindingsManagementView (imported)
      └─ ./components/findings/FindingsManagementView.tsx
         └─ findingsView.ts (helpers)
         └─ FindingsManagementView.test.tsx
```

---

## 📋 REFERENCIAS EN TODO EL PROYECTO

### Búsquedas por término:

**"Escaneo" aparece en 41 matches, 6 archivos:**
1. [App.tsx](src/Frontend/src/app/App.tsx) — 26 ocurrencias
   - Línea 591: NavItem label
   - Línea 1147: Renderizado condicional
   - Línea 1364: Definición ScanView
2. [AuditTaskMarker.tsx](src/Frontend/src/app/components/audit/AuditTaskMarker.tsx) — 5 ocurrencias
   - Línea 36: `title: 'Escaneo de fallos'`
   - Línea 61: Estimación de tiempo
3. [FindingsManagementView.test.tsx](src/Frontend/src/app/components/findings/FindingsManagementView.test.tsx) — 4 ocurrencias
4. [FindingsManagementView.tsx](src/Frontend/src/app/components/findings/FindingsManagementView.tsx) — 2 ocurrencias
5. [LandingPage.tsx](src/Frontend/src/app/components/landing/LandingPage.tsx) — 2 ocurrencias
6. [ScheduleManager.jsx](src/Frontend/src/components/ScheduleManager.jsx) — 1 ocurrencia

**"Validación" aparece en 2 matches, 1 archivo:**
1. [App.tsx](src/Frontend/src/app/App.tsx)
   - Línea 592: NavItem label
   - Línea 1150: Renderizado condicional

**"Gestión de Hallazgos" aparece en 3 matches, 2 archivos:**
1. [App.tsx](src/Frontend/src/app/App.tsx)
   - Línea 593: NavItem label
   - Línea 1151: Renderizado condicional
2. [findingsView.ts](src/Frontend/src/app/lib/findingsView.ts)
   - Línea 2: Comentario de archivo

**"Hallazgos" aparece en 30 matches, 7 archivos:**
- Ampliamente usado en toda la interfaz (ver referencias de hallazgos arriba)

---

## 🔄 FLUJO DE DATOS

### Flujo 1: Escaneo (Nuclei/SQLMap)

```
User clicks "Escaneo" NavItem
  ↓
activeTab = "Escaneo (Nuclei/SQLMap)"
  ↓
conditional render triggers ScanView (línea 1147)
  ↓
ScanView receives:
  ├─ targetUrl (from state)
  ├─ findings[] (populated after scan)
  ├─ isAuditing (true during scan)
  └─ reportStatus (string)
  ↓
ScanView displays:
  ├─ Finding count by severity
  ├─ Progress bar (if isAuditing)
  └─ Status message
```

### Flujo 2: Validación (Metasploit)

```
User clicks "Validación" NavItem
  ↓
activeTab = "Validación (Metasploit)"
  ↓
conditional render triggers MetasploitView (línea 1150)
  ↓
MetasploitView receives:
  └─ targetUrl
  ↓
MetasploitView displays:
  ├─ Active Meterpreter sessions
  ├─ Connection status
  └─ Compromised host info
```

### Flujo 3: Gestión de Hallazgos

```
User clicks "Gestión de Hallazgos" NavItem
  ↓
activeTab = "Gestión de Hallazgos"
  ↓
conditional render triggers FindingsManagementView (línea 1151)
  ↓
User enters scanId manually
  ↓
handleLoadScan() calls getScanDetail(scanId)
  ↓
API returns ScanDetailResponse with findings[]
  ↓
handleFetchVectors() chunks findings (max 10) and calls analyzeVectors()
  ↓
scopeFinding() called for each finding (HU-016)
  ↓
UI displays table with:
  ├─ Filtering (severity, confidence, false positive)
  ├─ Pagination (10 items/page)
  ├─ Mark FP button
  └─ Attack vector proposal
```

---

## 🎨 COMPONENTES Y ICONOS UTILIZADOS

| Sección | Icono | Importación | Color |
|---------|-------|-------------|-------|
| Escaneo | `<ScanLine />` | lucide-react | text-[var(--ax-accent)] |
| Validación | `<ShieldCheck />` | lucide-react | text-[var(--ax-brand)] |
| Gestión de Hallazgos | `<ListFilter />` | lucide-react | (por defecto) |

---

## 📚 REFERENCIAS ÚTILES

### Archivos principales:
- [App.tsx](src/Frontend/src/app/App.tsx) — Componente raíz (1700+ líneas)
- [FindingsManagementView.tsx](src/Frontend/src/app/components/findings/FindingsManagementView.tsx) — Componente de gestión (200+ líneas)
- [findingsView.ts](src/Frontend/src/app/lib/findingsView.ts) — Lógica pura de hallazgos
- [AuditTaskMarker.tsx](src/Frontend/src/app/components/audit/AuditTaskMarker.tsx) — Selector de tareas

### APIs utilizadas:
- `GET /api/jobs/{scanId}` — Obtiene detalles del escaneo
- `POST /api/ai/vectors/analyze` — Correlaciona vectores de ataque
- `POST /api/ai/findings/score` — Score de confianza de IA
- `POST /api/findings/{id}/false-positive` — Marca falso positivo

### HUs relacionadas:
- HU-009: Programación de escaneos (ScheduleManager.jsx)
- HU-010: Gestión de falsos positivos (FindingsManagementView)
- HU-014: Correlación de vectores de ataque
- HU-016: Validación con Pydantic (scoring)
- HU-019: Lighthouse (KPIs)
- HU-021: Gestión de hallazgos (FindingsManagementView)

---

**Generado por análisis automático del código frontend (grep + lectura de archivos)**
