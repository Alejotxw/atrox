import React, { useState, useEffect, useRef } from 'react';
import { 
  ShieldAlert, 
  Database, 
  Radar, 
  ScanLine, 
  Cpu, 
  History,
  Play,
  CheckCircle2,
  AlertTriangle,
  Info,
  Clock,
  ShieldCheck,
  Server,
  Network,
  FileText,
  Loader2,
  Search,
  Activity,
  Lock,
  MessageSquare,
  Calendar,
  ChevronRight,
  Zap,
  Target,
  Terminal,
  ListFilter,
  LogOut,
  QrCode,
  UserCheck,
  RefreshCw,
  Menu,
  X,
  Users
} from 'lucide-react';
import FindingsManagementView from './components/findings/FindingsManagementView';
import LoginForm from './components/auth/LoginForm';
import LandingPage from './components/landing/LandingPage';
import AdminPanel from './components/admin/AdminPanel';
import ScanConsole from './components/ScanConsole/ScanConsole';
import AuditTaskMarker, {
  DEFAULT_AUDIT_TASKS,
  countSelectedTasks,
  estimateAuditLabel,
  selectedTaskTitles,
  type AuditTasks,
} from './components/audit/AuditTaskMarker';
import {
  createScan,
  getScanDetail,
  analyzeVectors,
  sendChatMessage,
  downloadExecutiveReportPdf,
  downloadTechnicalReport,
  getHealth,
  getMeApi,
  logoutApi,
  setAuthToken,
  getAuthToken,
  ApiError,
  type AttackVector,
  type ScanDetailResponse,
  type GetScanDetailParams,
  type VulnSeverity,
  type HostFinding,
  type Job,
  listJobs,
} from './lib/api';
import {
  DASHBOARD_POLL_MS,
  EMPTY_KPIS,
  fetchDashboardKpis,
  type DashboardKpis,
} from './lib/dashboardMetrics';
import { prioritizeFindingsForAi } from './lib/findingsView';
import { normalizeTarget } from './lib/target';

// --- Tipos locales de la vista de hallazgos ---
type Severity = 'Crítico' | 'Alto' | 'Medio' | 'Bajo' | 'Info' | 'Desconocido';
type FindingStatus = 'checked' | 'unchecked' | 'na';
interface FindingRow {
  id: string;
  name: string;
  vector: string;
  severity: Severity;
  status: FindingStatus;
}

const SEVERITY_LABELS: Record<VulnSeverity, Severity> = {
  critical: 'Crítico',
  high: 'Alto',
  medium: 'Medio',
  low: 'Bajo',
  info: 'Info',
  unknown: 'Desconocido',
};

const mapSeverity = (sev: VulnSeverity): Severity => SEVERITY_LABELS[sev] ?? 'Desconocido';

const describeError = (err: unknown): string => {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
};

/** Evita mostrar el error crudo de npipe/Docker en la UI. */
const humanizeAuditToolError = (message: string | null | undefined): string => {
  const raw = (message || '').trim();
  if (!raw) return 'error desconocido';
  const lower = raw.toLowerCase();
  if (
    lower.includes('npipe') ||
    lower.includes('dockerdesktoplinuxengine') ||
    lower.includes('docker daemon') ||
    lower.includes('failed to connect to the docker') ||
    lower.includes('cannot connect to the docker') ||
    lower.includes('docker desktop no está')
  ) {
    return 'Docker Desktop no estaba en ejecución. Ábrelo, espera «Engine running» y vuelve a auditar.';
  }
  return raw;
};

// --- Sondeo de un scan hasta que quede 'done' o 'failed' ---
async function pollScanUntilDone(
  scanId: string,
  isCurrent: () => boolean,
  params?: GetScanDetailParams,
): Promise<ScanDetailResponse | null> {
  while (isCurrent()) {
    const detail = await getScanDetail(scanId, params);
    if (!isCurrent()) return null;
    if (detail.status === 'done' || detail.status === 'failed') return detail;
    await new Promise((res) => setTimeout(res, 1500));
  }
  return null;
}

function describeThreatLevel(vectors: AttackVector[]): { label: string; className: string } | null {
  if (vectors.length === 0) return null;
  const maxScore = Math.max(...vectors.map((v) => v.severity_score));
  if (maxScore >= 8) return { label: 'CRÍTICO', className: 'text-red-500' };
  if (maxScore >= 5) return { label: 'ALTO', className: 'text-orange-400' };
  if (maxScore >= 3) return { label: 'MEDIO', className: 'text-[var(--ax-warn)]' };
  return { label: 'BAJO', className: 'text-[var(--ax-info)]' };
}

export default function App() {
  // --- ESTADOS INTERACTIVOS ---
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(!!getAuthToken());
  const [showLogin, setShowLogin] = useState<boolean>(false);
  const [authenticatedUser, setAuthenticatedUser] = useState<string>('sysadmin');
  const [userRole, setUserRole] = useState<string>('SysAdmin');
  const isSuperAdmin = userRole === 'SysAdmin';
  const [sessionRemaining, setSessionRemaining] = useState<number | null>(null);

  const [activeTab, setActiveTab] = useState('Dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [targetUrl, setTargetUrl] = useState('corp.internal.uide.edu.ec');
  const [isAuditing, setIsAuditing] = useState(false);
  const [auditTasks, setAuditTasks] = useState<AuditTasks>(DEFAULT_AUDIT_TASKS);
  /** 1 = elegir tareas, 2 = objetivo e iniciar, 3 = seguimiento / resultados */
  const [dashStep, setDashStep] = useState<1 | 2 | 3>(1);
  
  const [reportStatus, setReportStatus] = useState('Generando');
  const [auditWarning, setAuditWarning] = useState<string | null>(null);
  const [findings, setFindings] = useState<FindingRow[]>([]);

  // --- KPIs globales reales (HU-019 / HU-010), fusionados en esta fila para evitar la duplicación con datos falsos ---
  const [kpis, setKpis] = useState<DashboardKpis>(EMPTY_KPIS);
  const [kpisLoading, setKpisLoading] = useState(true);
  const [kpisRefreshing, setKpisRefreshing] = useState(false);
  const [kpisError, setKpisError] = useState<string | null>(null);
  const kpisInFlight = useRef(false);
  const [showInsights, setShowInsights] = useState(true);
  const [discoveryAssets, setDiscoveryAssets] = useState<HostFinding[]>([]);
  const [attackVectors, setAttackVectors] = useState<AttackVector[]>([]);
  const [vectorAnalysisMeta, setVectorAnalysisMeta] = useState<{
    source: 'llm' | 'heuristic';
    model_used: string | null;
  } | null>(null);
  const [backendHealth, setBackendHealth] = useState<'checking' | 'online' | 'offline'>('checking');
  const [lastScanId, setLastScanId] = useState<string | null>(null);
  const [isExportingPdf, setIsExportingPdf] = useState(false);
  const [auditToken, setAuditToken] = useState(0);

  const auditRunIdRef = useRef(0);

  // --- VERIFICACIÓN DE SESIÓN MFA ACTIVA ---
  useEffect(() => {
    if (!getAuthToken()) {
      setIsAuthenticated(false);
      return;
    }

    const checkSession = async () => {
      try {
        const res = await getMeApi();
        setAuthenticatedUser(res.username);
        setUserRole(res.role);
        setSessionRemaining(res.seconds_remaining);
        setIsAuthenticated(true);
      } catch {
        setAuthToken(null);
        setIsAuthenticated(false);
        // Había una sesión previa (token expirado/inválido) — ir directo al
        // login en vez de la landing, igual que el comportamiento anterior.
        setShowLogin(true);
      }
    };
    checkSession();
  }, []);

  // Si una sesión de cuenta regular hereda 'Administración' como pestaña activa
  // (ej. tras cerrar sesión del sysadmin sin cambiar de pestaña primero), la
  // redirige a Dashboard — el backend ya bloquea el acceso, esto solo evita
  // un panel de contenido en blanco para el usuario regular.
  useEffect(() => {
    if (!isSuperAdmin && activeTab === 'Administración') {
      setActiveTab('Dashboard');
    }
  }, [isSuperAdmin, activeTab]);

  const handleLogout = async () => {
    try {
      await logoutApi();
    } catch {
      // Ignorar si falla la revocación en backend
    } finally {
      setAuthToken(null);
      setIsAuthenticated(false);
    }
  };

  // --- VERIFICACIÓN PERIÓDICA DE SALUD DEL BACKEND ---
  useEffect(() => {
    let cancelled = false;
    const checkHealth = async () => {
      try {
        await getHealth();
        if (!cancelled) setBackendHealth('online');
      } catch {
        if (!cancelled) setBackendHealth('offline');
      }
    };
    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  // --- INVALIDA CUALQUIER SONDEO EN CURSO AL DESMONTAR EL COMPONENTE ---
  useEffect(() => {
    return () => {
      auditRunIdRef.current += 1;
    };
  }, []);

  // --- POLLING REAL DE KPIs (HU-019): activos, puertos y vulnerabilidades críticas vía HU-010 ---
  const loadKpis = React.useCallback(async (isPoll = false) => {
    if (kpisInFlight.current) return;
    if (document.visibilityState === 'hidden') return;

    kpisInFlight.current = true;
    if (isPoll) setKpisRefreshing(true);
    else setKpisLoading(true);

    try {
      const next = await fetchDashboardKpis();
      setKpis(next);
      setKpisError(null);
    } catch (err) {
      const message =
        err instanceof ApiError
          ? `Backend ${err.status}: no se pudieron cargar métricas`
          : 'No se pudo conectar con el backend';
      setKpisError(message);
    } finally {
      kpisInFlight.current = false;
      setKpisLoading(false);
      setKpisRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadKpis(false);
    const id = window.setInterval(() => loadKpis(true), DASHBOARD_POLL_MS);

    const onVisibility = () => {
      if (document.visibilityState === 'visible') loadKpis(true);
    };
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      window.clearInterval(id);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [loadKpis]);

  // --- MOTOR REAL DE AUDITORÍA (pasos según Marcador de Tareas) ---
  const handleStartAudit = async () => {
    if (isAuditing || !targetUrl.trim()) return;
    if (countSelectedTasks(auditTasks) === 0) {
      alert('Marca al menos una tarea en el Marcador antes de iniciar la auditoría.');
      return;
    }

    auditRunIdRef.current += 1;
    const runId = auditRunIdRef.current;
    const isCurrent = () => auditRunIdRef.current === runId;

    const target = normalizeTarget(targetUrl);

    setIsAuditing(true);
    setDashStep(3);
    setAuditToken((n) => n + 1);
    setFindings([]);
    setAttackVectors([]);
    setVectorAnalysisMeta(null);
    setDiscoveryAssets([]);
    setShowInsights(false);
    setReportStatus('Iniciando');
    setAuditWarning(null);

    try {
      if (!target) {
        alert('Objetivo inválido tras normalizar — verifica que sea una IP o dominio.');
        setReportStatus('Error');
        setIsAuditing(false);
        return;
      }

      // Paso 1: Discovery (opcional)
      if (auditTasks.discovery) {
        const discoveryScan = await createScan(target, 'discovery', {
          port_range: '80,443,8080,8443',
        });
        if (!isCurrent()) return;

        const discoveryDetail = await pollScanUntilDone(discoveryScan.scan_id, isCurrent);
        if (!isCurrent() || !discoveryDetail) return;

        if (discoveryDetail.status === 'failed') {
          alert(`Descubrimiento fallido: ${discoveryDetail.error ?? 'error desconocido'}`);
          setReportStatus('Error');
          return;
        }

        setDiscoveryAssets(discoveryDetail.assets);
        loadKpis(true);
      }

      let items: Awaited<ReturnType<typeof getScanDetail>>['findings']['items'] = [];
      let vulnScanId: string | null = null;
      let hasCves = false;

      // Paso 2: Nuclei (opcional)
      if (auditTasks.vulnscan) {
        const vulnScan = await createScan(target, 'vulnscan', {
          severity: 'critical,high,medium',
          type: 'http',
        });
        if (!isCurrent()) return;
        vulnScanId = String(vulnScan.scan_id);
        setLastScanId(vulnScanId);

        await pollScanUntilDone(vulnScanId, isCurrent, { pageSize: 100 });
        if (!isCurrent()) return;

        const vulnDetail = await getScanDetail(vulnScanId, { pageSize: 100 });
        if (!isCurrent()) return;

        const rawNuclei =
          vulnDetail.status === 'failed' && !vulnDetail.findings.items.length
            ? []
            : vulnDetail.findings.items;
        items = rawNuclei;

        hasCves = items.some(
          (f) => !f.template_id.startsWith('audit:') && !f.template_id.startsWith('recon:'),
        );

        if (vulnDetail.status === 'failed' && !hasCves) {
          setAuditWarning(
            `Nuclei no completó (${humanizeAuditToolError(vulnDetail.error)}). Se muestran hallazgos informativos del mismo escaneo.`,
          );
        } else if (vulnDetail.error && !hasCves) {
          setAuditWarning(
            `Nuclei parcial: ${humanizeAuditToolError(vulnDetail.error)}. Impacto/Trazabilidad/Reportes usan el resultado persistido del escaneo ${vulnScanId}.`,
          );
        } else if (!hasCves) {
          setAuditWarning(
            `Escaneo ${vulnScanId} sin CVEs Nuclei. Impacto y Trazabilidad muestran el resultado real (recon/negativo); los reportes PDF/HTML usan la misma fuente.`,
          );
        }

        setFindings(
          items.map((f) => ({
            id: f.template_id,
            name: f.name,
            vector: f.matched_at || f.host,
            severity: mapSeverity(f.severity),
            status: (f.severity === 'info' ? 'na' : 'unchecked') as FindingStatus,
          })),
        );
      }

      // Paso 3: vectores (opcional; requiere hallazgos de Nuclei)
      if (auditTasks.vectorAnalysis && items.length > 0) {
        try {
          const analysis = await analyzeVectors(prioritizeFindingsForAi(items));
          if (!isCurrent()) return;
          setAttackVectors(analysis.vectors);
          setVectorAnalysisMeta({ source: analysis.source, model_used: analysis.model_used });
          if (analysis.source === 'heuristic' && hasCves) {
            setAuditWarning(
              (prev) =>
                prev ??
                'Correlación de impacto heurística sobre los hallazgos reales de este escaneo.',
            );
          }
        } catch {
          if (!isCurrent()) return;
          setAttackVectors(
            items.slice(0, 8).map((f, idx) => ({
              rank: idx + 1,
              vector_id: `local:${f.template_id}`,
              name: f.name,
              severity_score:
                f.severity === 'critical'
                  ? 10
                  : f.severity === 'high'
                    ? 7.5
                    : f.severity === 'medium'
                      ? 5
                      : f.severity === 'low'
                        ? 2.5
                        : 1,
              finding_ids: [f.template_id],
              chain: [f.matched_at || f.host, f.name],
              justification: f.description || `Resultado del escaneo ${vulnScanId}.`,
              estimated_impact:
                f.severity === 'info'
                  ? 'Informativo — sin CVE explotable confirmado en esta corrida'
                  : `Proporcional a severidad ${f.severity}`,
            })),
          );
          setVectorAnalysisMeta({ source: 'heuristic', model_used: null });
          setAuditWarning(
            (prev) =>
              prev ??
              'Correlación por API no disponible; impacto generado localmente desde los hallazgos del escaneo.',
          );
        }
      } else if (!auditTasks.vectorAnalysis) {
        setAttackVectors([]);
        setVectorAnalysisMeta(null);
      } else {
        setAttackVectors([]);
        setVectorAnalysisMeta(null);
      }

      if (!isCurrent()) return;
      setShowInsights(true);
      if (!auditTasks.vulnscan && auditTasks.discovery) {
        setReportStatus('Completado (solo reconocimiento)');
      } else {
        setReportStatus(hasCves ? 'Completado' : 'Completado (resultado informativo)');
      }
      loadKpis(true);
    } catch (err) {
      if (!isCurrent()) return;
      alert(`Error durante la auditoría: ${describeError(err)}`);
      setReportStatus('Error');
    } finally {
      if (isCurrent()) setIsAuditing(false);
    }
  };

  const handleExportPdf = async () => {
    if (!lastScanId) {
      alert('Ejecute una auditoría o escaneo de seguridad antes de exportar el reporte ejecutivo en PDF.');
      return;
    }
    setIsExportingPdf(true);
    try {
      await downloadExecutiveReportPdf(lastScanId);
    } catch (err) {
      alert(`Error al exportar reporte ejecutivo: ${describeError(err)}`);
    } finally {
      setIsExportingPdf(false);
    }
  };

  const handleExportTechnical = async (format: 'pdf' | 'html') => {
    if (!lastScanId) {
      alert('Ejecute una auditoría o escaneo de seguridad antes de exportar el reporte técnico.');
      return;
    }
    setIsExportingPdf(true);
    try {
      await downloadTechnicalReport(lastScanId, format);
    } catch (err) {
      alert(`Error al exportar reporte técnico (${format.toUpperCase()}): ${describeError(err)}`);
    } finally {
      setIsExportingPdf(false);
    }
  };

  // --- Selecciona pestaña y cierra el panel lateral en móvil/tablet ---
  const selectTab = (tab: string) => {
    setActiveTab(tab);
    setSidebarOpen(false);
  };

  if (!isAuthenticated) {
    if (!showLogin) {
      return <LandingPage onRequestLogin={() => setShowLogin(true)} />;
    }
    return (
      <LoginForm
        onSuccess={(user, role) => { setAuthenticatedUser(user); setUserRole(role); setIsAuthenticated(true); }}
        onBack={() => setShowLogin(false)}
      />
    );
  }

  return (
    <div className="atrox-shell flex h-screen w-full overflow-hidden">

      {/* Fondo oscurecido al abrir el panel lateral en móvil/tablet */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* 1. Sidebar Izquierdo - Navegación y Branding */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-[280px] bg-[var(--ax-surface)] border-r border-[var(--ax-border)] flex flex-col shrink-0 transform transition-transform duration-300 ease-in-out lg:static lg:translate-x-0 ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="p-5 border-b border-[var(--ax-border)]">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-9 h-9 rounded-md bg-[var(--ax-brand)] flex items-center justify-center shrink-0">
                <ShieldAlert className="text-white w-4.5 h-4.5 w-[18px] h-[18px]" />
              </div>
              <div className="min-w-0">
                <h1 className="text-white font-semibold text-lg tracking-tight leading-none">Atrox</h1>
                <p className="text-[11px] text-[var(--ax-muted)] mt-1 leading-snug">
                  UIDE · Pentesting asistido por IA
                </p>
              </div>
            </div>
            <button
              onClick={() => setSidebarOpen(false)}
              className="p-1.5 text-[var(--ax-muted)] hover:text-white hover:bg-[var(--ax-surface-2)] rounded-md lg:hidden shrink-0"
              aria-label="Cerrar menú"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="p-3 flex-1 overflow-y-auto">
          <h2 className="text-[10px] font-semibold text-[var(--ax-muted)] uppercase tracking-[0.12em] mb-2 px-2">
            Navegación
          </h2>
          <nav className="space-y-0.5">
            <NavItem icon={<Radar />} label="Dashboard" active={activeTab === 'Dashboard'} onClick={() => selectTab('Dashboard')} />
            <NavItem icon={<Network />} label="Reconocimiento" active={activeTab === 'Reconocimiento (Nmap)'} onClick={() => selectTab('Reconocimiento (Nmap)')} />
            <NavItem icon={<ScanLine />} label="Escaneo" active={activeTab === 'Escaneo (Nuclei/SQLMap)'} onClick={() => selectTab('Escaneo (Nuclei/SQLMap)')} />
            <NavItem icon={<ShieldCheck />} label="Validación" active={activeTab === 'Validación (Metasploit)'} onClick={() => selectTab('Validación (Metasploit)')} />
            <NavItem icon={<ListFilter />} label="Gestión de Hallazgos" active={activeTab === 'Gestión de Hallazgos'} onClick={() => selectTab('Gestión de Hallazgos')} />
            <NavItem icon={<Cpu />} label="Motor IA" badge="Chat" active={activeTab === 'Motor Ollama IA'} onClick={() => selectTab('Motor Ollama IA')} />
            <NavItem icon={<History />} label="Historial" active={activeTab === 'Historial de Trabajos'} onClick={() => selectTab('Historial de Trabajos')} />
            {isSuperAdmin && (
              <NavItem icon={<Users />} label="Administración" active={activeTab === 'Administración'} onClick={() => selectTab('Administración')} />
            )}
          </nav>
        </div>

        <div className="p-4 border-t border-[var(--ax-border)]">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-9 h-9 rounded-lg bg-[var(--ax-surface-2)] flex items-center justify-center border border-[var(--ax-border)] text-[var(--ax-muted)] shrink-0">
                <UserCheck className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <p className="text-xs font-semibold text-white truncate">{authenticatedUser}</p>
                <p className="text-[10px] text-[var(--ax-info)] font-medium">Sesión MFA activa</p>
              </div>
            </div>
            <button
              onClick={handleLogout}
              title="Cerrar sesión"
              className="p-2 text-slate-400 hover:text-red-300 hover:bg-red-500/10 rounded-lg transition-all shrink-0"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

        {/* 2. Header — objetivo + acción primaria (menos ruido) */}
        <header className="border-b border-[var(--ax-border)] bg-[var(--ax-surface)] flex flex-wrap items-center justify-between gap-3 px-4 sm:px-6 py-3 shrink-0">
          <div className="flex items-center gap-3 flex-wrap min-w-0">
            <button
              onClick={() => setSidebarOpen(true)}
              className="p-2 text-[var(--ax-muted)] hover:text-white hover:bg-[var(--ax-surface-2)] rounded-md lg:hidden shrink-0"
              aria-label="Abrir menú"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div
              className={`atrox-status ${
                backendHealth === 'online'
                  ? 'is-online'
                  : backendHealth === 'offline'
                    ? 'is-offline'
                    : ''
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-sm ${
                  backendHealth === 'online'
                    ? 'bg-[var(--ax-info)]'
                    : backendHealth === 'offline'
                      ? 'bg-[var(--ax-danger)]'
                      : 'bg-[var(--ax-muted)]'
                }`}
              />
              Backend {backendHealth === 'online' ? 'online' : backendHealth === 'offline' ? 'offline' : '…'}
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap w-full sm:w-auto">
            {(dashStep >= 2 || isAuditing) && (
              <div className="relative flex-1 sm:flex-none min-w-0">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Target className="h-4 w-4 text-[var(--ax-muted)]" />
                </div>
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  disabled={isAuditing}
                  className="atrox-field w-full sm:w-56 md:w-72 !py-2 !text-sm"
                  placeholder="Objetivo (IP o dominio)"
                />
              </div>
            )}
            <button
              onClick={() => {
                if (dashStep === 1) {
                  if (countSelectedTasks(auditTasks) === 0) {
                    alert('Marca al menos una tarea para continuar.');
                    return;
                  }
                  setDashStep(2);
                  return;
                }
                void handleStartAudit();
              }}
              disabled={
                isAuditing ||
                (dashStep >= 2 && (!targetUrl.trim() || countSelectedTasks(auditTasks) === 0))
              }
              className="atrox-btn-primary px-4 py-2 text-sm flex items-center gap-2 whitespace-nowrap"
              title={estimateAuditLabel(auditTasks)}
            >
              {isAuditing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin shrink-0" />
                  En curso…
                </>
              ) : dashStep === 1 ? (
                <>
                  Continuar
                  <ChevronRight className="w-4 h-4 shrink-0" />
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current shrink-0" />
                  Iniciar
                </>
              )}
            </button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-4 sm:p-5 lg:p-6">
          <div className="max-w-[1200px] mx-auto atrox-main">
            {/* Dashboard permanece montado (oculto con CSS) para no reiniciar la consola SSE. */}
            <div className={activeTab === 'Dashboard' ? 'atrox-main' : 'hidden'}>
                {/* Indicador de pasos */}
                <nav className="atrox-steps" aria-label="Progreso de la auditoría">
                  {(
                    [
                      { n: 1 as const, label: 'Tareas', hint: 'Qué ejecutar' },
                      { n: 2 as const, label: 'Objetivo', hint: 'IP o dominio' },
                      { n: 3 as const, label: 'Resultados', hint: 'Consola y KPIs' },
                    ] as const
                  ).map((s) => (
                    <button
                      key={s.n}
                      type="button"
                      className={`atrox-step text-left ${
                        dashStep === s.n ? 'is-current' : dashStep > s.n ? 'is-done' : ''
                      }`}
                      onClick={() => {
                        if (isAuditing && s.n < 3) return;
                        if (s.n === 2 && countSelectedTasks(auditTasks) === 0) return;
                        if (s.n === 3 && dashStep < 2 && !lastScanId) return;
                        setDashStep(s.n);
                      }}
                    >
                      <span className="atrox-step-num">
                        {dashStep > s.n ? '✓' : s.n}
                      </span>
                      <span className="min-w-0">
                        <span className="atrox-step-label block truncate">{s.label}</span>
                        <span className="atrox-step-hint truncate">{s.hint}</span>
                      </span>
                    </button>
                  ))}
                </nav>

                {/* PASO 1 — solo tareas */}
                {dashStep === 1 && (
                  <AuditTaskMarker
                    tasks={auditTasks}
                    onChange={setAuditTasks}
                    disabled={isAuditing}
                    onContinue={() => setDashStep(2)}
                  />
                )}

                {/* PASO 2 — objetivo e iniciar */}
                {dashStep === 2 && (
                  <section className="atrox-panel" aria-label="Paso 2: objetivo">
                    <div className="atrox-hero-card border-b border-[var(--ax-border)]">
                      <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--ax-brand)] mb-2">
                        Paso 2 de 3
                      </p>
                      <h2 className="atrox-section-title text-[1.35rem]">¿Contra qué objetivo?</h2>
                      <p className="atrox-section-sub">
                        Escribe la IP o el dominio que quieres auditar. Luego inicia y verás el
                        progreso en la consola.
                      </p>
                    </div>

                    <div className="p-4 sm:p-5 space-y-5">
                      <div>
                        <p className="text-[12px] text-[var(--ax-muted)] mb-2 font-medium">
                          Tareas que vas a ejecutar
                        </p>
                        <div className="flex flex-wrap items-center justify-between gap-3">
                          <AuditTaskMarker
                            tasks={auditTasks}
                            onChange={setAuditTasks}
                            compact
                          />
                          <button
                            type="button"
                            disabled={isAuditing}
                            onClick={() => setDashStep(1)}
                            className="atrox-btn-ghost text-[12px] px-3 py-1.5"
                          >
                            Cambiar tareas
                          </button>
                        </div>
                      </div>

                      <div>
                        <label className="block text-[12px] font-semibold text-[var(--ax-muted)] mb-2 uppercase tracking-wide">
                          Objetivo
                        </label>
                        <div className="relative max-w-xl">
                          <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                            <Target className="h-4 w-4 text-[var(--ax-muted)]" />
                          </div>
                          <input
                            type="text"
                            value={targetUrl}
                            onChange={(e) => setTargetUrl(e.target.value)}
                            disabled={isAuditing}
                            className="atrox-field"
                            placeholder="Ej. 192.168.1.10 o corp.empresa.edu.ec"
                          />
                        </div>
                        <p className="text-[12px] text-[var(--ax-muted)] mt-2">
                          Tiempo estimado: <strong className="text-white font-medium">{estimateAuditLabel(auditTasks)}</strong>
                        </p>
                      </div>

                      <div className="atrox-task-footer !mt-2">
                        <button
                          type="button"
                          disabled={isAuditing}
                          onClick={() => setDashStep(1)}
                          className="atrox-btn-ghost text-[13px] px-4 py-2.5"
                        >
                          ← Volver a tareas
                        </button>
                        <button
                          type="button"
                          onClick={handleStartAudit}
                          disabled={
                            isAuditing ||
                            !targetUrl.trim() ||
                            countSelectedTasks(auditTasks) === 0
                          }
                          className="atrox-btn-primary atrox-btn-lg inline-flex items-center gap-2"
                        >
                          {isAuditing ? (
                            <>
                              <Loader2 className="w-4 h-4 animate-spin" />
                              Auditoría en curso…
                            </>
                          ) : (
                            <>
                              <Play className="w-4 h-4 fill-current" />
                              Iniciar auditoría
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  </section>
                )}

                {/* PASO 3 — resultados / seguimiento */}
                {dashStep === 3 && (
                  <>
                    <section className="atrox-panel">
                      <div className="p-4 sm:px-5 sm:py-4 flex flex-wrap items-center justify-between gap-3">
                        <div className="min-w-0">
                          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--ax-brand)] mb-1">
                            Paso 3 de 3 · Seguimiento
                          </p>
                          <h2 className="text-[15px] font-semibold text-white truncate">
                            {isAuditing ? 'Auditoría en curso' : lastScanId ? 'Últimos resultados' : 'Listo para monitorear'}
                          </h2>
                          <p className="text-[12px] text-[var(--ax-muted)] mt-0.5 truncate">
                            Objetivo: <span className="text-[var(--ax-text)]">{targetUrl || '—'}</span>
                            {' · '}
                            {selectedTaskTitles(auditTasks).join(', ') || 'sin tareas'}
                          </p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {!isAuditing && (
                            <button
                              type="button"
                              onClick={() => setDashStep(1)}
                              className="atrox-btn-ghost text-xs px-3 py-1.5"
                            >
                              Nueva auditoría
                            </button>
                          )}
                          {!isAuditing && (
                            <button
                              type="button"
                              onClick={() => setDashStep(2)}
                              className="atrox-btn-primary text-xs px-3 py-1.5 inline-flex items-center gap-1.5"
                            >
                              <Play className="w-3.5 h-3.5 fill-current" />
                              Volver a iniciar
                            </button>
                          )}
                        </div>
                      </div>
                    </section>

                    <section aria-label="KPIs de seguridad">
                      <div className="atrox-toolbar mb-3">
                        <div>
                          <h2 className="atrox-section-title">Riesgo global</h2>
                          <p className="atrox-section-sub">
                            Se actualiza cada {DASHBOARD_POLL_MS / 1000}s ·{' '}
                            {kpis.lastUpdated
                              ? new Date(kpis.lastUpdated).toLocaleTimeString()
                              : 'aún sin datos'}
                          </p>
                        </div>
                        <div className="atrox-toolbar-actions">
                          <button
                            type="button"
                            onClick={() => loadKpis(true)}
                            disabled={kpisRefreshing || kpisLoading}
                            className="atrox-btn-ghost text-xs px-2.5 py-1.5 inline-flex items-center gap-1.5 disabled:opacity-50"
                          >
                            {kpisRefreshing || kpisLoading ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <RefreshCw className="w-3.5 h-3.5" />
                            )}
                            Actualizar
                          </button>
                          <button
                            type="button"
                            onClick={handleExportPdf}
                            disabled={isExportingPdf || !lastScanId}
                            className="atrox-btn-ghost text-xs px-2.5 py-1.5 inline-flex items-center gap-1.5 disabled:opacity-40"
                            title="Reporte ejecutivo PDF"
                          >
                            <FileText className="w-3.5 h-3.5" />
                            Ejecutivo
                          </button>
                          <button
                            type="button"
                            onClick={() => handleExportTechnical('pdf')}
                            disabled={isExportingPdf || !lastScanId}
                            className="atrox-btn-ghost text-xs px-2.5 py-1.5 inline-flex items-center gap-1.5 disabled:opacity-40"
                            title="Reporte técnico PDF"
                          >
                            <Terminal className="w-3.5 h-3.5" />
                            Técnico
                          </button>
                          <button
                            type="button"
                            onClick={() => handleExportTechnical('html')}
                            disabled={isExportingPdf || !lastScanId}
                            className="atrox-btn-ghost text-xs px-2.5 py-1.5 inline-flex items-center gap-1.5 disabled:opacity-40"
                            title="Reporte técnico HTML"
                          >
                            <Zap className="w-3.5 h-3.5" />
                            HTML
                          </button>
                        </div>
                      </div>

                      {kpisError && (
                        <div className="text-xs text-[var(--ax-warn)] border border-[var(--ax-border)] rounded-md px-3 py-2 mb-3 bg-[var(--ax-surface)]">
                          {kpisError}. Se muestran últimos valores conocidos o ceros.
                        </div>
                      )}

                      <div className="atrox-kpi-grid">
                        <MetricCard
                          title="Hosts descubiertos"
                          value={String(kpis.assets)}
                          module="Nmap"
                          icon={<Network />}
                          color="blue"
                          loading={kpisLoading}
                        />
                        <MetricCard
                          title="Puertos y servicios"
                          value={String(kpis.ports)}
                          module="Nmap"
                          icon={<Server />}
                          color="indigo"
                          loading={kpisLoading}
                        />
                        <MetricCard
                          title="Vulnerabilidades críticas"
                          value={String(kpis.criticalVulns)}
                          module="Nuclei"
                          icon={<AlertTriangle />}
                          color="red"
                          loading={kpisLoading}
                        />
                        <MetricCard
                          title="Estado del reporte"
                          value={reportStatus}
                          module="Reportes"
                          icon={<FileText />}
                          color="gold"
                        />
                      </div>
                    </section>

                    {auditWarning && (
                      <div className="flex items-start gap-3 text-xs text-[var(--ax-warn)] border border-[var(--ax-border)] rounded-md px-3 py-2.5 bg-[var(--ax-surface)]">
                        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                        <div>
                          <span className="font-semibold text-[var(--ax-text)]">Aviso.</span> {auditWarning}
                        </div>
                      </div>
                    )}

                    <div className="atrox-work-grid">
                      <ScanConsole
                        targetUrl={targetUrl}
                        auditToken={auditToken}
                        isAuditing={isAuditing}
                      />

                      <div className="atrox-panel overflow-hidden flex flex-col relative min-w-0 min-h-[320px]">
                        <div className="atrox-panel-head">
                          <div className="flex items-center gap-2 min-w-0">
                            <Cpu className="w-4 h-4 text-[var(--ax-muted)] shrink-0" />
                            <h3 className="font-semibold text-white text-[13px]">Análisis de impacto</h3>
                          </div>
                          <span className="text-[10px] text-[var(--ax-muted)] font-mono shrink-0">
                            {vectorAnalysisMeta?.source === 'llm'
                              ? vectorAnalysisMeta.model_used
                              : 'heurístico'}
                          </span>
                        </div>

                        <div className="p-4 flex-1 overflow-y-auto relative">
                          {!showInsights ? (
                            <div className="atrox-empty absolute inset-0">
                              <Cpu className="w-8 h-8 mb-2 opacity-35" />
                              <p>
                                {auditTasks.vectorAnalysis
                                  ? 'Cuando termine el escaneo, aquí verás los vectores priorizados.'
                                  : 'No marcaste “Análisis de impacto” en las tareas.'}
                              </p>
                            </div>
                          ) : (
                            <div>
                              {attackVectors.length === 0 ? (
                                <div className="flex items-start gap-3 border border-[var(--ax-border)] rounded-md p-3 bg-[var(--ax-bg)]">
                                  <Info className="w-4 h-4 text-[var(--ax-muted)] shrink-0 mt-0.5" />
                                  <p className="text-[13px] text-[var(--ax-muted)] leading-relaxed">
                                    Sin vectores en esta corrida
                                    {lastScanId ? ` (${lastScanId.slice(0, 8)}…)` : ''}.
                                  </p>
                                </div>
                              ) : (
                                <>
                                  {(() => {
                                    const threat = describeThreatLevel(attackVectors);
                                    return threat ? (
                                      <div className="mb-3 flex items-center justify-between border border-[var(--ax-border)] rounded-md p-2.5 bg-[var(--ax-bg)]">
                                        <span className="text-[11px] text-[var(--ax-muted)] font-semibold">
                                          Amenaza
                                        </span>
                                        <div className={`flex items-center gap-2 font-semibold text-sm ${threat.className}`}>
                                          <AlertTriangle className="w-4 h-4" />
                                          {threat.label}
                                        </div>
                                      </div>
                                    ) : null;
                                  })()}

                                  <div className="space-y-2">
                                    {attackVectors.map((vector) => (
                                      <div
                                        key={vector.vector_id}
                                        className="bg-[var(--ax-bg)] px-3 py-2.5 rounded-md border border-[var(--ax-border)]"
                                      >
                                        <div className="flex items-center justify-between mb-1 gap-2">
                                          <span className="text-[13px] font-semibold text-white">{vector.name}</span>
                                          <span className="text-[11px] font-mono text-[var(--ax-muted)] shrink-0">
                                            {vector.severity_score}
                                          </span>
                                        </div>
                                        <p className="text-[12px] text-[var(--ax-muted)] leading-relaxed mb-1">
                                          {vector.justification}
                                        </p>
                                        <p className="text-[11px] text-[var(--ax-muted)]">
                                          Impacto: {vector.estimated_impact}
                                        </p>
                                      </div>
                                    ))}
                                  </div>
                                </>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="atrox-panel overflow-hidden">
                      <div className="atrox-panel-head">
                        <h3 className="font-semibold text-white text-[13px] flex items-center gap-2">
                          <Database className="w-4 h-4 text-[var(--ax-muted)]" />
                          Trazabilidad de hallazgos
                        </h3>
                        <span className="text-[11px] text-[var(--ax-muted)] font-medium">
                          {lastScanId
                            ? `${findings.length} · ${lastScanId.slice(0, 8)}…`
                            : `${findings.length} hallazgo(s)`}
                        </span>
                      </div>
                      <div className="overflow-x-auto min-h-[140px]">
                        {findings.length === 0 ? (
                          <div className="atrox-empty">
                            <History className="w-7 h-7 mb-2 opacity-35" />
                            <p>
                              {isAuditing
                                ? 'Los hallazgos aparecerán aquí conforme avance el escaneo.'
                                : 'Aún no hay hallazgos. Inicia una auditoría desde el paso 2.'}
                            </p>
                          </div>
                        ) : (
                          <table className="w-full text-left text-sm">
                            <thead className="bg-[var(--ax-surface-2)] text-[11px] uppercase text-[var(--ax-muted)] border-b border-[var(--ax-border)] font-semibold tracking-wider">
                              <tr>
                                <th className="px-4 py-3">ID</th>
                                <th className="px-4 py-3">Vulnerabilidad</th>
                                <th className="px-4 py-3">Vector</th>
                                <th className="px-4 py-3">Criticidad</th>
                                <th className="px-4 py-3">Estado</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-[var(--ax-border)]">
                              {findings.map((finding) => (
                                <TableRow
                                  key={finding.id}
                                  id={finding.id}
                                  name={finding.name}
                                  vector={finding.vector}
                                  severity={finding.severity}
                                  status={finding.status}
                                />
                              ))}
                            </tbody>
                          </table>
                        )}
                      </div>
                    </div>
                  </>
                )}
            </div>

            {activeTab === 'Reconocimiento (Nmap)' && (
              <ReconView targetUrl={targetUrl} assets={discoveryAssets} isAuditing={isAuditing} />
            )}
            {activeTab === 'Escaneo (Nuclei/SQLMap)' && (
              <ScanView targetUrl={targetUrl} findings={findings} isAuditing={isAuditing} reportStatus={reportStatus} />
            )}
            {activeTab === 'Validación (Metasploit)' && <MetasploitView targetUrl={targetUrl} />}
            {activeTab === 'Gestión de Hallazgos' && <FindingsManagementView />}
            {activeTab === 'Motor Ollama IA' && <OllamaView findings={findings} targetUrl={targetUrl} />}
            {activeTab === 'Historial de Trabajos' && <HistoryView />}
            {activeTab === 'Administración' && isSuperAdmin && <AdminPanel />}

          </div>
        </div>
      </div>
    </div>
  );
}

/* --- Componentes Auxiliares --- */

const NavItem = ({ icon, label, active, badge, onClick }: { icon: React.ReactElement, label: string, active?: boolean, badge?: string, onClick?: () => void }) => (
  <button
    onClick={onClick}
    className={`atrox-nav-item ${active ? 'is-active' : ''}`}
  >
    <div className="flex items-center gap-2.5">
      {React.cloneElement(icon, {
        className: `w-4 h-4 ${active ? 'text-[var(--ax-text)]' : 'text-[var(--ax-muted)]'}`,
      })}
      <span className="text-[13px] text-left">{label}</span>
    </div>
    {badge && (
      <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded border border-[var(--ax-border)] text-[var(--ax-muted)]">
        {badge}
      </span>
    )}
  </button>
);

const MetricCard = ({ title, value, module, icon, color, loading }: { title: string, value: string, module: string, icon: React.ReactElement, color: string, loading?: boolean }) => {
  const iconTone: Record<string, string> = {
    blue: 'text-[var(--ax-info)]',
    indigo: 'text-[var(--ax-muted)]',
    red: 'text-[var(--ax-danger)]',
    gold: 'text-[var(--ax-muted)]',
  };

  return (
    <div className="atrox-kpi">
      <div className="flex justify-between items-start gap-2">
        <p className="text-[12px] text-[var(--ax-muted)] font-medium leading-snug">{title}</p>
        <span className={`shrink-0 ${iconTone[color] ?? 'text-[var(--ax-muted)]'}`}>
          {React.cloneElement(icon, { className: 'w-4 h-4' })}
        </span>
      </div>
      <div>
        <p className="text-[1.65rem] font-semibold text-white tracking-tight leading-none truncate mt-3">
          {loading ? '—' : value}
        </p>
        <p className="text-[11px] text-[var(--ax-muted)] mt-2">{module}</p>
      </div>
    </div>
  );
};

const TableRow = ({ id, name, vector, severity, status }: { id: string, name: string, vector: string, severity: Severity, status: string }) => {
  const getSeverityBadge = (sev: Severity) => {
    switch(sev) {
      case 'Crítico': return <span className="inline-flex items-center px-2.5 py-1 rounded-md text-[11px] font-semibold bg-[rgba(224,122,122,0.12)] text-[#e07a7a] border border-[rgba(224,122,122,0.28)] uppercase tracking-wider">Crítico</span>;
      case 'Alto': return <span className="inline-flex items-center px-2.5 py-1 rounded-md text-[11px] font-semibold bg-[rgba(224,168,92,0.12)] text-[#e0a85c] border border-[rgba(224,168,92,0.28)] uppercase tracking-wider">Alto</span>;
      case 'Medio': return <span className="inline-flex items-center px-2.5 py-1 rounded-md text-[11px] font-semibold bg-[rgba(197,206,221,0.1)] text-[var(--ax-accent)] border border-[rgba(197,206,221,0.22)] uppercase tracking-wider">Medio</span>;
      case 'Bajo': return <span className="inline-flex items-center px-2.5 py-1 rounded-md text-[11px] font-semibold bg-[rgba(126,160,255,0.1)] text-[var(--ax-info)] border border-[rgba(126,160,255,0.22)] uppercase tracking-wider">Bajo</span>;
      case 'Info': return <span className="inline-flex items-center px-2.5 py-1 rounded-md text-[11px] font-semibold bg-white/5 text-[var(--ax-muted)] border border-[var(--ax-border)] uppercase tracking-wider">Info</span>;
      case 'Desconocido': return <span className="inline-flex items-center px-2.5 py-1 rounded-md text-[11px] font-semibold bg-white/5 text-[var(--ax-muted)] border border-[var(--ax-border)] uppercase tracking-wider">N/D</span>;
      default: return null;
    }
  };

  const getStatusBadge = (stat: string) => {
    switch(stat) {
      case 'checked': return (
        <div className="flex items-center gap-2 text-[var(--ax-info)] text-[13px] font-medium bg-[rgba(142,160,184,0.08)] px-3 py-1.5 rounded-lg border border-[rgba(142,160,184,0.2)] w-fit">
          <CheckCircle2 className="w-4 h-4" />
          <span>Confirmado</span>
        </div>
      );
      case 'unchecked': return (
        <div className="flex items-center gap-2 text-[var(--ax-muted)] text-[13px] font-medium bg-black/20 px-3 py-1.5 rounded-lg border border-[var(--ax-border)] w-fit">
          <Clock className="w-4 h-4" />
          <span>Pendiente</span>
        </div>
      );
      case 'na': return (
        <div className="flex items-center gap-2 text-slate-500 text-[13px] font-medium px-3 py-1.5 w-fit">
          <Info className="w-4 h-4" />
          <span>No aplica</span>
        </div>
      );
    }
  };

  return (
    <tr className="hover:bg-slate-800/40 transition-colors group">
      <td className="px-6 py-4 text-slate-400 font-mono text-[13px] group-hover:text-slate-300">{id}</td>
      <td className="px-6 py-4 font-semibold text-slate-200 text-[14px]">{name}</td>
      <td className="px-6 py-4 text-slate-400 font-mono text-[13px]">{vector}</td>
      <td className="px-6 py-4">{getSeverityBadge(severity)}</td>
      <td className="px-6 py-4">{getStatusBadge(status)}</td>
    </tr>
  );
};

/* --- Vistas de los Módulos Secundarios --- */

const ReconView = ({
  targetUrl,
  assets,
  isAuditing,
}: {
  targetUrl: string;
  assets: HostFinding[];
  isAuditing: boolean;
}) => {
  const upHosts = assets.filter((h) => h.status === 'up');
  const totalPorts = assets.reduce((sum, h) => sum + h.ports.length, 0);
  const primaryHost = upHosts[0] ?? assets[0] ?? null;

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 bg-[#1E293B] border border-slate-700 rounded-xl p-6 shadow-lg">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-blue-500/10 rounded-lg"><Network className="w-5 h-5 text-blue-400" /></div>
            <h3 className="text-white font-bold text-lg">Objetivo Activo</h3>
          </div>
          <p className="text-2xl font-mono text-blue-400 mb-1 break-all">{targetUrl}</p>
          <p className="text-slate-400 text-sm">
            {primaryHost ? `IP Resuelta: ${primaryHost.address}` : 'Aún no hay un escaneo de reconocimiento en esta sesión.'}
          </p>
          <div className="mt-6 pt-6 border-t border-slate-700/50">
            <div className="flex justify-between items-center mb-2">
              <span className="text-slate-400 text-sm">Estado de Red</span>
              {isAuditing ? (
                <span className="text-[var(--ax-accent)] text-sm font-bold flex items-center gap-1">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" /> Escaneando...
                </span>
              ) : primaryHost ? (
                <span className={`text-sm font-bold flex items-center gap-1 ${primaryHost.status === 'up' ? 'text-[var(--ax-info)]' : 'text-red-400'}`}>
                  <span className={`w-2 h-2 rounded-full ${primaryHost.status === 'up' ? 'bg-[var(--ax-info)] animate-pulse' : 'bg-red-400'}`}></span>
                  {primaryHost.status.toUpperCase()}
                </span>
              ) : (
                <span className="text-slate-500 text-sm font-bold">SIN DATOS</span>
              )}
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400 text-sm">Hosts activos</span>
              <span className="text-white text-sm font-mono">{upHosts.length} / {assets.length}</span>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2 bg-[#1E293B] border border-slate-700 rounded-xl p-0 shadow-lg overflow-hidden flex flex-col">
          <div className="px-6 py-4 border-b border-slate-700 bg-slate-800/50 flex flex-wrap gap-3 justify-between items-center">
            <h3 className="text-white font-bold flex items-center gap-2"><Server className="w-4 h-4 text-slate-400" /> Puertos y Servicios Descubiertos</h3>
            <span className="text-xs text-slate-400 font-medium px-3 py-1 bg-slate-800 rounded-full border border-slate-700">
              {totalPorts} puerto{totalPorts !== 1 ? 's' : ''} abierto{totalPorts !== 1 ? 's' : ''}
            </span>
          </div>
          <div className="flex-1 overflow-x-auto overflow-y-auto p-0">
            {assets.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-slate-500">
                <Network className="w-8 h-8 mb-3 opacity-50" />
                <p className="text-sm">
                  {isAuditing
                    ? 'Escaneando puertos y servicios...'
                    : 'Ejecuta "Iniciar Auditoría Automatizada" para ver resultados reales de Nmap.'}
                </p>
              </div>
            ) : (
              <table className="w-full text-left text-sm">
                <thead className="bg-[#0B1121] text-xs uppercase text-slate-400 border-b border-slate-700 font-semibold">
                  <tr>
                    <th className="px-6 py-3">Host</th>
                    <th className="px-6 py-3">Puerto</th>
                    <th className="px-6 py-3">Protocolo</th>
                    <th className="px-6 py-3">Servicio</th>
                    <th className="px-6 py-3">Versión (Banner Grab)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {assets.flatMap((host) =>
                    host.ports.length > 0 ? (
                      host.ports.map((port) => (
                        <tr key={`${host.address}:${port.port}`} className="hover:bg-slate-800/40">
                          <td className="px-6 py-3 text-slate-300 font-mono text-xs">{host.address}</td>
                          <td className="px-6 py-3 font-mono text-blue-400">{port.port}</td>
                          <td className="px-6 py-3 text-slate-400">{port.protocol}</td>
                          <td className="px-6 py-3 text-slate-200">{port.service || '—'}</td>
                          <td className="px-6 py-3 text-slate-400 text-xs font-mono">{port.version || '—'}</td>
                        </tr>
                      ))
                    ) : (
                      <tr key={host.address} className="hover:bg-slate-800/40">
                        <td className="px-6 py-3 text-slate-300 font-mono text-xs">{host.address}</td>
                        <td colSpan={4} className="px-6 py-3 text-slate-500">Sin puertos abiertos detectados</td>
                      </tr>
                    ),
                  )}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

const ScanView = ({
  targetUrl,
  findings,
  isAuditing,
  reportStatus,
}: {
  targetUrl: string;
  findings: FindingRow[];
  isAuditing: boolean;
  reportStatus: string;
}) => {
  const bySeverity: Record<Severity, number> = {
    'Crítico': 0, 'Alto': 0, 'Medio': 0, 'Bajo': 0, 'Info': 0, 'Desconocido': 0,
  };
  findings.forEach((f) => { bySeverity[f.severity] += 1; });

  const severityCards: { label: Severity; color: string }[] = [
    { label: 'Crítico', color: 'text-red-400' },
    { label: 'Alto', color: 'text-orange-400' },
    { label: 'Medio', color: 'text-[var(--ax-accent)]' },
    { label: 'Bajo', color: 'text-sky-400' },
  ];

  return (
    <div className="grid grid-cols-1 gap-6 animate-in fade-in duration-300">
      <div className="bg-[#1E293B] border border-slate-700 rounded-xl p-6 shadow-lg">
        <div className="flex flex-wrap gap-4 justify-between items-end mb-6">
          <div>
            <h3 className="text-white font-bold text-lg flex items-center gap-2 mb-1"><ScanLine className="w-5 h-5 text-[var(--ax-accent)]" /> Resultados de Escaneo (Nuclei)</h3>
            <p className="text-slate-400 text-sm break-all">Plantillas de vulnerabilidad web, CVEs y misconfigurations sobre {targetUrl}.</p>
          </div>
          <div className="text-right">
            <p className="text-3xl font-black text-white">{findings.length}</p>
            <p className="text-xs text-[var(--ax-accent)] font-bold uppercase tracking-widest">
              {isAuditing ? 'En Curso' : reportStatus}
            </p>
          </div>
        </div>

        {isAuditing && (
          <div className="w-full bg-[var(--ax-surface-2)] h-2 mb-6 overflow-hidden border border-[var(--ax-border)] rounded">
            <div className="bg-[var(--ax-brand)] h-full w-2/3" />
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {severityCards.map((card) => (
            <div key={card.label} className="bg-slate-800/50 p-4 rounded-lg border border-slate-700/50">
              <p className="text-xs text-slate-500 uppercase font-bold mb-1">{card.label}</p>
              <p className={`text-xl font-mono ${card.color}`}>{bySeverity[card.label]}</p>
            </div>
          ))}
        </div>

        {findings.length === 0 && !isAuditing && (
          <p className="text-slate-500 text-sm mt-6 text-center py-6">
            Aún no hay resultados de Nuclei en esta sesión — ejecuta "Iniciar Auditoría Automatizada".
          </p>
        )}
      </div>
    </div>
  );
};

const MetasploitView = ({ targetUrl }: { targetUrl: string }) => (
  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 lg:h-[500px] animate-in fade-in duration-300">
    <div className="lg:col-span-1 flex flex-col gap-6">
      <div className="bg-[#1E293B] border border-slate-700 rounded-xl p-6 shadow-lg flex-1">
        <h3 className="text-white font-bold flex items-center gap-2 mb-4"><ShieldCheck className="w-5 h-5 text-[var(--ax-brand)]" /> Sesiones Activas</h3>
        
        <div className="bg-[var(--ax-info)]/10 border border-[rgba(142,160,184,0.25)] rounded-lg p-4 mb-4">
          <div className="flex justify-between items-start mb-2">
            <span className="text-xs text-[var(--ax-info)] font-bold uppercase tracking-widest">Meterpreter 1</span>
            <span className="w-2 h-2 bg-[var(--ax-info)] rounded-full animate-pulse"></span>
          </div>
          <p className="text-white text-sm font-mono mb-1">192.168.1.105:4444</p>
          <p className="text-slate-400 text-xs">UID: www-data (33) | OS: Linux</p>
        </div>

        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 opacity-50">
          <div className="flex justify-between items-start mb-2">
            <span className="text-xs text-slate-500 font-bold uppercase tracking-widest">Shell 2 (Muerta)</span>
            <span className="w-2 h-2 bg-red-500 rounded-full"></span>
          </div>
          <p className="text-slate-400 text-sm font-mono mb-1">192.168.1.105:4445</p>
          <p className="text-slate-500 text-xs">Conexión cerrada por el host.</p>
        </div>
      </div>
    </div>
    
    <div className="lg:col-span-2 bg-[#000000] border border-slate-700 rounded-xl shadow-2xl flex flex-col overflow-hidden relative min-h-[320px]">
      <div className="bg-[#1E293B] px-4 py-2 border-b border-slate-700 flex items-center gap-2 min-w-0">
        <Terminal className="w-4 h-4 text-slate-400 shrink-0" />
        <span className="text-xs font-mono text-slate-300 truncate">msfconsole - {targetUrl}</span>
      </div>
      <div className="p-4 font-mono text-[13px] text-slate-300 leading-relaxed overflow-x-auto overflow-y-auto flex-1">
        <div className="text-slate-400 mb-4">
          <pre className="text-[var(--ax-brand)] font-bold">
{`       =[ metasploit v6.3.20-dev                          ]
+ -- --=[ 2320 exploits - 1214 auxiliary - 413 post       ]
+ -- --=[ 964 payloads - 45 encoders - 11 nops            ]`}
          </pre>
        </div>
        <div className="mb-2"><span className="text-blue-400">msf6</span> <span className="text-red-400">exploit</span>(multi/http/apache_normalize_path) {'>'} set RHOSTS 192.168.1.105</div>
        <div className="mb-2 text-slate-400">RHOSTS ={'>'} 192.168.1.105</div>
        <div className="mb-2"><span className="text-blue-400">msf6</span> <span className="text-red-400">exploit</span>(multi/http/apache_normalize_path) {'>'} exploit</div>
        <div className="mb-1 text-slate-400">[*] Started reverse TCP handler on 192.168.1.50:4444</div>
        <div className="mb-1 text-slate-400">[*] Running automatic check ("set AutoCheck false" to disable)</div>
        <div className="mb-1 text-[var(--ax-info)]">[+] The target is vulnerable.</div>
        <div className="mb-1 text-slate-400">[*] Executing payload...</div>
        <div className="mb-1 text-[var(--ax-info)]">[*] Meterpreter session 1 opened (192.168.1.50:4444 -{'>'} 192.168.1.105:39842) at 2026-06-06 14:04:12</div>
        <div className="mt-4 flex items-center gap-2">
          <span className="text-blue-400 border-b border-blue-400">meterpreter</span> {'>'} <span className="w-2 h-4 bg-slate-300 animate-pulse"></span>
        </div>
      </div>
    </div>
  </div>
);

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

const OllamaView = ({ findings, targetUrl }: { findings: FindingRow[]; targetUrl: string }) => {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [modelUsed, setModelUsed] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, sending]);

  const buildContext = (): string | undefined => {
    if (findings.length === 0) return undefined;
    const bySeverity = findings.reduce<Record<string, number>>((acc, f) => {
      acc[f.severity] = (acc[f.severity] ?? 0) + 1;
      return acc;
    }, {});
    const summary = Object.entries(bySeverity).map(([sev, count]) => `${count} ${sev}`).join(', ');
    const list = findings.slice(0, 10).map((f) => `- [${f.severity}] ${f.name} en ${f.vector}`).join('\n');
    return `Objetivo: ${targetUrl}. Hallazgos actuales (${findings.length}): ${summary}.\n${list}`;
  };

  const handleSend = async () => {
    const message = input.trim();
    if (!message || sending) return;
    setInput('');
    setError(null);
    setMessages((prev) => [...prev, { role: 'user', content: message }]);
    setSending(true);
    try {
      const res = await sendChatMessage(message, buildContext());
      setMessages((prev) => [...prev, { role: 'assistant', content: res.response }]);
      setModelUsed(res.model_used);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setSending(false);
    }
  };

  const handleNewChat = () => {
    setMessages([]);
    setError(null);
  };

  const userQuestions = messages.filter((m) => m.role === 'user');

  return (
    <div className="flex flex-col md:flex-row md:h-[500px] border border-slate-700 rounded-xl overflow-hidden shadow-lg animate-in fade-in duration-300">
      <div className="w-full md:w-64 bg-[#1E293B] border-b md:border-b-0 md:border-r border-slate-700 p-4 flex flex-col shrink-0">
        <button
          onClick={handleNewChat}
          className="w-full bg-[var(--ax-brand)] hover:bg-[var(--ax-brand-hover)] text-white py-2 rounded-lg text-sm font-semibold flex items-center justify-center gap-2 mb-6 transition-colors"
        >
          <MessageSquare className="w-4 h-4" /> Nueva Conversación
        </button>
        <div className="text-xs text-slate-500 font-bold uppercase tracking-widest mb-3">Preguntas de esta sesión</div>
        <div className="space-y-2 flex-1 overflow-y-auto">
          {userQuestions.length === 0 ? (
            <p className="text-xs text-slate-600 italic">Aún no has hecho ninguna pregunta.</p>
          ) : (
            userQuestions.map((q, i) => (
              <div key={i} className="bg-slate-800/50 text-slate-400 text-sm p-3 rounded-lg border border-slate-700/50">
                <p className="truncate">{q.content}</p>
              </div>
            ))
          )}
        </div>
        {modelUsed && <p className="text-[10px] text-slate-600 mt-3 truncate">Modelo: {modelUsed}</p>}
      </div>

      <div className="flex-1 bg-[#0F172A] flex flex-col relative min-w-0">
        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {messages.length === 0 ? (
            <div className="h-full min-h-[240px] flex flex-col items-center justify-center text-slate-500 text-center px-4">
              <Cpu className="w-10 h-10 text-[var(--ax-accent)]/30 mb-4" />
              <p className="text-sm">
                {findings.length > 0
                  ? `Pregúntale a la IA sobre los ${findings.length} hallazgo(s) del escaneo actual.`
                  : 'Aún no hay hallazgos en esta sesión — igual puedes preguntar lo que quieras.'}
              </p>
            </div>
          ) : (
            messages.map((m, i) => (
              <div key={i} className={`flex gap-4 max-w-3xl ${m.role === 'user' ? '' : 'ml-auto flex-row-reverse'}`}>
                <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${m.role === 'user' ? 'bg-slate-700' : 'bg-[var(--ax-accent)]/20 border border-[var(--ax-accent)]/30'}`}>
                  {m.role === 'user' ? <Lock className="w-4 h-4 text-slate-300" /> : <Cpu className="w-4 h-4 text-[var(--ax-accent)]" />}
                </div>
                <div className={`rounded-2xl p-4 text-sm whitespace-pre-wrap ${m.role === 'user' ? 'bg-slate-800 rounded-tl-none text-slate-200' : 'bg-[var(--ax-accent)]/10 border border-[var(--ax-accent)]/20 rounded-tr-none text-slate-300'}`}>
                  {m.content}
                </div>
              </div>
            ))
          )}
          {sending && (
            <div className="flex gap-4 max-w-3xl ml-auto flex-row-reverse">
              <div className="w-8 h-8 rounded-full bg-[var(--ax-accent)]/20 flex items-center justify-center shrink-0 border border-[var(--ax-accent)]/30">
                <Cpu className="w-4 h-4 text-[var(--ax-accent)]" />
              </div>
              <div className="bg-[var(--ax-accent)]/10 border border-[var(--ax-accent)]/20 rounded-2xl rounded-tr-none p-4 text-sm text-slate-400 flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin" /> Pensando...
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {error && (
          <div className="mx-6 mb-3 text-xs text-red-300 bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-2">
            {error}
          </div>
        )}

        <div className="p-4 border-t border-slate-800 bg-[#1E293B]">
          <div className="relative">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleSend(); }}
              disabled={sending}
              placeholder="Pregunta sobre los hallazgos, impacto o mitigación..."
              className="w-full bg-[#0B1121] border border-slate-700 rounded-lg pl-4 pr-12 py-3 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-[var(--ax-accent)]/50 focus:ring-1 focus:ring-[var(--ax-accent)]/50 disabled:opacity-50"
            />
            <button
              onClick={handleSend}
              disabled={sending || !input.trim()}
              className="absolute right-2 top-2 bottom-2 bg-[var(--ax-accent)] hover:bg-[var(--ax-accent)] disabled:opacity-50 disabled:cursor-not-allowed text-[#0B1121] p-2 rounded-md transition-colors"
            >
              {sending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-current" />}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

function formatJobDuration(job: Job): string {
  if (!job.started_at || !job.finished_at) return '—';
  const ms = new Date(job.finished_at).getTime() - new Date(job.started_at).getTime();
  const totalSeconds = Math.max(0, Math.round(ms / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

function jobResultSummary(job: Job): string {
  if (job.status !== 'done' || !job.result) return '—';
  if (job.job_type === 'discovery') {
    const hosts = Array.isArray(job.result.hosts) ? (job.result.hosts as { status?: string }[]) : [];
    const upHosts = hosts.filter((h) => h.status === 'up').length;
    return `${upHosts} host(s) activo(s)`;
  }
  const findingsArr = Array.isArray(job.result.findings) ? (job.result.findings as { severity?: string }[]) : [];
  const critical = findingsArr.filter((f) => f.severity === 'critical').length;
  return `${findingsArr.length} hallazgo(s), ${critical} crítico(s)`;
}

const HistoryView = () => {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await listJobs();
        if (!cancelled) setJobs(data);
      } catch (err) {
        if (!cancelled) setError(describeError(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const sorted = [...jobs].sort((a, b) => b.created_at.localeCompare(a.created_at));
  const query = search.trim().toLowerCase();
  const filtered = query
    ? sorted.filter((job) => {
        const target = String(job.params?.target ?? '').toLowerCase();
        return target.includes(query) || job.created_at.toLowerCase().includes(query);
      })
    : sorted;

  const handleDownload = async (job: Job) => {
    setDownloadingId(job.id);
    try {
      await downloadExecutiveReportPdf(job.id);
    } catch (err) {
      alert(`Error al descargar reporte: ${describeError(err)}`);
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <div className="bg-[#1E293B] border border-slate-700 rounded-xl overflow-hidden shadow-lg animate-in fade-in duration-300">
      <div className="px-6 py-5 border-b border-slate-700 bg-slate-800/50 flex flex-wrap gap-3 justify-between items-center">
        <h3 className="font-bold text-white flex items-center gap-2"><History className="w-5 h-5 text-slate-400" /> Historial de Trabajos (Nmap/Nuclei)</h3>
        <div className="relative w-full sm:w-auto">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Buscar por objetivo..."
            className="w-full sm:w-64 bg-[#0B1121] border border-slate-700 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-300 placeholder-slate-500 focus:outline-none"
          />
        </div>
      </div>
      <div className="overflow-x-auto">
        {loading ? (
          <div className="flex items-center justify-center gap-2 py-16 text-slate-500">
            <Loader2 className="w-5 h-5 animate-spin" /> Cargando historial...
          </div>
        ) : error ? (
          <div className="text-center py-16 text-red-400 text-sm">{error}</div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-slate-500">
            <History className="w-8 h-8 mb-3 opacity-50" />
            <p className="text-sm">{jobs.length === 0 ? 'Aún no hay trabajos registrados en el backend.' : 'Sin resultados para esa búsqueda.'}</p>
          </div>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="bg-[#0B1121] text-xs uppercase text-slate-400 border-b border-slate-700 font-semibold tracking-wider">
              <tr>
                <th className="px-6 py-4">Fecha</th>
                <th className="px-6 py-4">Objetivo</th>
                <th className="px-6 py-4">Tipo</th>
                <th className="px-6 py-4">Duración</th>
                <th className="px-6 py-4">Resultado</th>
                <th className="px-6 py-4">Estado</th>
                <th className="px-6 py-4">Reporte</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {filtered.map((job) => (
                <tr key={job.id} className="hover:bg-slate-800/40">
                  <td className="px-6 py-4 text-slate-400 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <Calendar className="w-3 h-3 shrink-0" /> {new Date(job.created_at).toLocaleString()}
                    </div>
                  </td>
                  <td className="px-6 py-4 text-white font-mono">{String(job.params?.target ?? '—')}</td>
                  <td className="px-6 py-4 text-slate-300">{job.job_type === 'discovery' ? 'Reconocimiento' : 'Vulnerabilidades'}</td>
                  <td className="px-6 py-4 text-slate-400">{formatJobDuration(job)}</td>
                  <td className="px-6 py-4 text-slate-300">{jobResultSummary(job)}</td>
                  <td className="px-6 py-4">
                    {job.status === 'done' ? (
                      <span className="text-[var(--ax-info)] flex items-center gap-1"><CheckCircle2 className="w-4 h-4" /> Completado</span>
                    ) : job.status === 'failed' ? (
                      <span className="text-red-400 flex items-center gap-1" title={job.error ?? undefined}><AlertTriangle className="w-4 h-4" /> Error</span>
                    ) : (
                      <span className="text-[var(--ax-accent)] flex items-center gap-1"><Loader2 className="w-4 h-4 animate-spin" /> {job.status === 'running' ? 'En curso' : 'Pendiente'}</span>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    {job.job_type === 'vulnscan' && job.status === 'done' ? (
                      <button
                        onClick={() => handleDownload(job)}
                        disabled={downloadingId === job.id}
                        className="text-[var(--ax-accent)] hover:text-white hover:underline flex items-center gap-1 disabled:opacity-50"
                      >
                        {downloadingId === job.id ? <Loader2 className="w-3 h-3 animate-spin" /> : <FileText className="w-3 h-3" />} PDF
                      </button>
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
