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
  X
} from 'lucide-react';
import FindingsManagementView from './components/findings/FindingsManagementView';
import LoginForm from './components/auth/LoginForm';
import ScanConsole from './components/ScanConsole/ScanConsole';
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
  if (maxScore >= 3) return { label: 'MEDIO', className: 'text-[#D4AF37]' };
  return { label: 'BAJO', className: 'text-blue-400' };
}

export default function App() {
  // --- ESTADOS INTERACTIVOS ---
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(!!getAuthToken());
  const [authenticatedUser, setAuthenticatedUser] = useState<string>('sysadmin');
  const [sessionRemaining, setSessionRemaining] = useState<number | null>(null);

  const [activeTab, setActiveTab] = useState('Dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [targetUrl, setTargetUrl] = useState('corp.internal.uide.edu.ec');
  const [isAuditing, setIsAuditing] = useState(false);
  
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
        setSessionRemaining(res.seconds_remaining);
        setIsAuthenticated(true);
      } catch {
        setAuthToken(null);
        setIsAuthenticated(false);
      }
    };
    checkSession();
  }, []);

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

  // --- MOTOR REAL DE AUDITORÍA (discovery -> vulnscan -> análisis de vectores; consola en vivo vía SSE HU-020) ---
  const handleStartAudit = async () => {
    if (isAuditing || !targetUrl.trim()) return;

    auditRunIdRef.current += 1;
    const runId = auditRunIdRef.current;
    const isCurrent = () => auditRunIdRef.current === runId;

    const target = normalizeTarget(targetUrl);

    setIsAuditing(true);
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

      // Paso 1: Discovery rápido (puertos web; 1-1024 tarda varios minutos)
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

      // Los KPIs de hosts/puertos se reflejan solos vía el polling real (HU-019) al terminar el job.
      loadKpis(true);

      // Paso 2: Nuclei — mismos hallazgos que verán los reportes PDF/HTML (job result).
      const vulnScan = await createScan(target, 'vulnscan', {
        severity: 'critical,high,medium',
        type: 'http',
      });
      if (!isCurrent()) return;
      const vulnScanId = String(vulnScan.scan_id);
      setLastScanId(vulnScanId);

      await pollScanUntilDone(vulnScanId, isCurrent, { pageSize: 100 });
      if (!isCurrent()) return;

      // Releer el MISMO scan_id que usan los reportes (fuente única: CVEs o resultado informativo).
      const vulnDetail = await getScanDetail(vulnScanId, { pageSize: 100 });
      if (!isCurrent()) return;

      const rawNuclei =
        vulnDetail.status === 'failed' && !vulnDetail.findings.items.length
          ? []
          : vulnDetail.findings.items;
      // Backend enriquece con superficie Nmap / resultado negativo si Nuclei vino vacío.
      const items = rawNuclei;

      const hasCves = items.some(
        (f) => !f.template_id.startsWith('audit:') && !f.template_id.startsWith('recon:'),
      );

      if (vulnDetail.status === 'failed' && !hasCves) {
        setAuditWarning(
          `Nuclei no completó (${vulnDetail.error ?? 'error'}). Se muestran hallazgos informativos del mismo escaneo (alineados con los reportes).`,
        );
      } else if (vulnDetail.error && !hasCves) {
        setAuditWarning(
          `Nuclei parcial: ${vulnDetail.error}. Impacto/Trazabilidad/Reportes usan el resultado persistido del escaneo ${vulnScanId}.`,
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

      // Paso 3: vectores sobre la misma lista que Trazabilidad/Reportes.
      if (items.length > 0) {
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
          // Fallback local: un vector por hallazgo para que Impacto nunca quede vacío.
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
      } else {
        setAttackVectors([]);
        setVectorAnalysisMeta(null);
      }

      if (!isCurrent()) return;
      setShowInsights(true);
      setReportStatus(hasCves ? 'Completado' : 'Completado (resultado informativo)');
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
    return <LoginForm onSuccess={(user) => { setAuthenticatedUser(user); setIsAuthenticated(true); }} />;
  }

  return (
    <div className="flex h-screen w-full bg-[#0F172A] text-slate-300 font-sans overflow-hidden">

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
        className={`fixed inset-y-0 left-0 z-50 w-[280px] lg:w-[300px] bg-[#0B1121] border-r border-slate-800 flex flex-col shrink-0 transform transition-transform duration-300 ease-in-out lg:static lg:translate-x-0 ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="p-6 border-b border-slate-800">
          <div className="flex items-center justify-between gap-2 mb-3">
            <div className="flex items-center gap-4 min-w-0">
              <div className="w-12 h-12 rounded-xl bg-[#7A1C3E] flex items-center justify-center shadow-lg shadow-[#7A1C3E]/20 shrink-0">
                <ShieldAlert className="text-white w-7 h-7" />
              </div>
              <div className="min-w-0">
                <h1 className="text-white font-bold text-xl leading-none mb-1">UIDE</h1>
                <p className="text-[10px] text-slate-400 font-semibold tracking-wider uppercase leading-tight">Facultad de Ciencias<br/>Técnicas</p>
              </div>
            </div>
            <button
              onClick={() => setSidebarOpen(false)}
              className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-all lg:hidden shrink-0"
              aria-label="Cerrar menú"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
          <p className="text-xs text-[#D4AF37] mt-2 italic font-medium">Powered by Arizona State University</p>
        </div>

        <div className="p-5 flex-1 overflow-y-auto">
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-4 px-2">AI-Pentest Framework v1.0</h2>
          <nav className="space-y-1.5">
            <NavItem icon={<Radar />} label="Dashboard" active={activeTab === 'Dashboard'} onClick={() => selectTab('Dashboard')} />
            <NavItem icon={<Network />} label="Reconocimiento (Nmap)" active={activeTab === 'Reconocimiento (Nmap)'} onClick={() => selectTab('Reconocimiento (Nmap)')} />
            <NavItem icon={<ScanLine />} label="Escaneo (Nuclei/SQLMap)" active={activeTab === 'Escaneo (Nuclei/SQLMap)'} onClick={() => selectTab('Escaneo (Nuclei/SQLMap)')} />
            <NavItem icon={<ShieldCheck />} label="Validación (Metasploit)" active={activeTab === 'Validación (Metasploit)'} onClick={() => selectTab('Validación (Metasploit)')} />
            <NavItem icon={<ListFilter />} label="Gestión de Hallazgos" active={activeTab === 'Gestión de Hallazgos'} onClick={() => selectTab('Gestión de Hallazgos')} />
            <NavItem icon={<Cpu />} label="Motor Ollama IA" badge="Llama 3" active={activeTab === 'Motor Ollama IA'} onClick={() => selectTab('Motor Ollama IA')} />
            <NavItem icon={<History />} label="Historial de Trabajos" active={activeTab === 'Historial de Trabajos'} onClick={() => selectTab('Historial de Trabajos')} />
          </nav>
        </div>

        <div className="p-5 border-t border-slate-800">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-9 h-9 rounded-xl bg-[#7A1C3E]/20 flex items-center justify-center border border-[#7A1C3E]/40 text-[#D4AF37] shrink-0">
                <UserCheck className="w-5 h-5" />
              </div>
              <div className="min-w-0">
                <p className="text-xs font-semibold text-white tracking-wide truncate">{authenticatedUser}</p>
                <p className="text-[10px] text-emerald-400 font-medium flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                  MFA Activo (Root)
                </p>
              </div>
            </div>
            <button
              onClick={handleLogout}
              title="Cerrar Sesión MFA"
              className="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-all border border-transparent hover:border-red-500/20 shrink-0"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

        {/* 2. Header Superior - Status del Sistema */}
        <header className="bg-[#1E293B]/80 backdrop-blur-md border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 px-4 sm:px-8 py-3 shrink-0">
          <div className="flex items-center gap-3 flex-wrap min-w-0">
            <button
              onClick={() => setSidebarOpen(true)}
              className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-all lg:hidden shrink-0"
              aria-label="Abrir menú"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className={`flex items-center gap-2.5 bg-[#0B1121] px-4 py-2 rounded-full border shadow-inner ${
              backendHealth === 'online' ? 'border-green-500/30' : backendHealth === 'offline' ? 'border-red-500/30' : 'border-slate-700'
            }`}>
              <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${
                backendHealth === 'online'
                  ? 'bg-green-500 animate-pulse shadow-[0_0_8px_rgba(34,197,94,0.6)]'
                  : backendHealth === 'offline'
                  ? 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]'
                  : 'bg-slate-500 animate-pulse'
              }`}></div>
              <span className={`text-xs font-semibold tracking-wide whitespace-nowrap ${
                backendHealth === 'online' ? 'text-green-400' : backendHealth === 'offline' ? 'text-red-400' : 'text-slate-400'
              }`}>
                Backend Atrox: {backendHealth === 'online' ? 'ONLINE' : backendHealth === 'offline' ? 'DESCONECTADO' : 'Verificando...'}
              </span>
            </div>
            <div className="hidden md:flex items-center gap-2.5 bg-[#0B1121] px-4 py-2 rounded-full border border-slate-700 shadow-inner">
              <Database className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              <span className="text-xs text-slate-300 font-semibold tracking-wide">
                Análisis de vectores: {vectorAnalysisMeta?.source === 'llm'
                  ? `IA (${vectorAnalysisMeta.model_used})`
                  : 'Motor heurístico'} · Almacenamiento JSONL
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3 flex-wrap w-full sm:w-auto">
            <div className="relative flex-1 sm:flex-none min-w-0">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                <Network className="h-4 w-4 text-slate-500" />
              </div>
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={isAuditing}
                className="block w-full sm:w-56 md:w-72 pl-10 pr-4 py-2.5 border border-slate-700 rounded-lg leading-5 bg-[#0B1121] text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent sm:text-sm font-mono transition-shadow disabled:opacity-50"
                placeholder="Objetivo (IP o Dominio)"
              />
            </div>
            <button
              onClick={handleStartAudit}
              disabled={isAuditing || !targetUrl.trim()}
              className="bg-[#7A1C3E] hover:bg-[#90244B] disabled:bg-[#7A1C3E]/50 disabled:cursor-not-allowed text-white px-5 py-2.5 rounded-lg text-sm font-semibold flex items-center gap-2.5 transition-all shadow-lg shadow-[#7A1C3E]/30 border border-[#7A1C3E] hover:border-[#A62A56] disabled:border-transparent whitespace-nowrap"
            >
              {isAuditing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin shrink-0" />
                  <span className="hidden sm:inline">Auditoría en Curso...</span>
                  <span className="sm:hidden">En curso...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current shrink-0" />
                  <span className="hidden sm:inline">Iniciar Auditoría Automatizada</span>
                  <span className="sm:hidden">Iniciar Auditoría</span>
                </>
              )}
            </button>
            <button
              onClick={handleExportPdf}
              disabled={isExportingPdf || !lastScanId}
              className="bg-gradient-to-r from-[#3182CE] to-[#2B6CB0] hover:from-[#2B6CB0] hover:to-[#2C5282] disabled:opacity-50 disabled:cursor-not-allowed text-white px-3.5 py-2.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all shadow-md border border-blue-500/30 whitespace-nowrap"
              title="Exportar reporte ejecutivo resumido en PDF para Directores de TI (HU-023)"
            >
              {isExportingPdf ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0" />
              ) : (
                <FileText className="w-3.5 h-3.5 shrink-0" />
              )}
              <span className="hidden sm:inline">Reporte Ejecutivo PDF</span>
            </button>
            <button
              onClick={() => handleExportTechnical('pdf')}
              disabled={isExportingPdf || !lastScanId}
              className="bg-gradient-to-r from-[#2D3748] to-[#1A202C] hover:from-[#1A202C] hover:to-[#0F172A] disabled:opacity-50 disabled:cursor-not-allowed text-white px-3.5 py-2.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all shadow-md border border-slate-600/40 whitespace-nowrap"
              title="Exportar reporte técnico detallado en PDF con PoC y comandos de remediación para SysAdmins (HU-024)"
            >
              <Terminal className="w-3.5 h-3.5 text-purple-400 shrink-0" />
              <span className="hidden sm:inline">Reporte Técnico PDF</span>
            </button>
            <button
              onClick={() => handleExportTechnical('html')}
              disabled={isExportingPdf || !lastScanId}
              className="bg-gradient-to-r from-[#0D9488] to-[#0F766E] hover:from-[#0F766E] hover:to-[#115E59] disabled:opacity-50 disabled:cursor-not-allowed text-white px-3.5 py-2.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all shadow-md border border-teal-500/30 whitespace-nowrap"
              title="Exportar reporte técnico interactivo en HTML con PoC y comandos para SysAdmins (HU-024)"
            >
              <Zap className="w-3.5 h-3.5 text-teal-300 shrink-0" />
              <span className="hidden sm:inline">Reporte Técnico HTML</span>
            </button>
          </div>
        </header>

        {/* Scrollable Dashboard Area */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-[#0F172A]">
          <div className="max-w-[1600px] mx-auto space-y-8">
            
            {/* MAIN CONTENT VIEWS */}
            {/* Dashboard permanece montado (oculto con CSS, no desmontado) para que la Consola de
                Ejecución (SSE) y su historial no se reinicien al cambiar de pestaña y volver. */}
            <div className={activeTab === 'Dashboard' ? '' : 'hidden'}>
                {/* HU-019 — KPIs globales reales desde HU-010 (polling sin recarga cada {DASHBOARD_POLL_MS / 1000}s) */}
                <section className="space-y-3 animate-in fade-in duration-300" aria-label="KPIs de seguridad">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h2 className="text-sm font-bold text-white tracking-wide">
                        Riesgo global — KPIs en vivo
                      </h2>
                      <p className="text-[11px] text-slate-500 mt-0.5">
                        Fuente: HU-010 · actualización cada {DASHBOARD_POLL_MS / 1000}s · última:{' '}
                        {kpis.lastUpdated ? new Date(kpis.lastUpdated).toLocaleTimeString() : '—'}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => loadKpis(true)}
                      disabled={kpisRefreshing || kpisLoading}
                      className="inline-flex items-center gap-2 text-xs font-semibold text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-600 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
                    >
                      {kpisRefreshing || kpisLoading ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <RefreshCw className="w-3.5 h-3.5" />
                      )}
                      Actualizar
                    </button>
                  </div>

                  {kpisError && (
                    <div className="text-xs text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-lg px-4 py-2">
                      {kpisError}. Se muestran últimos valores conocidos o ceros.
                    </div>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
                    <MetricCard
                      title="Hosts Descubiertos"
                      value={String(kpis.assets)}
                      module="Módulo Nmap (Discovery)"
                      icon={<Network />}
                      color="blue"
                      loading={kpisLoading}
                    />
                    <MetricCard
                      title="Puertos y Servicios"
                      value={String(kpis.ports)}
                      module="Módulo Nmap"
                      icon={<Server />}
                      color="indigo"
                      loading={kpisLoading}
                    />
                    <MetricCard
                      title="Vulnerabilidades Críticas"
                      value={String(kpis.criticalVulns)}
                      module="Módulo Nuclei"
                      icon={<AlertTriangle />}
                      color="red"
                      loading={kpisLoading}
                    />
                    <MetricCard
                      title="Estado del Reporte"
                      value={reportStatus}
                      module="Módulo ReportLab"
                      icon={<FileText />}
                      color="gold"
                    />
                  </div>
                </section>

                {auditWarning && (
                  <div className="flex items-start gap-3 text-xs text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-lg px-4 py-3 animate-in fade-in duration-300">
                    <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold">Auditoría parcial.</span> {auditWarning}. Los resultados de reconocimiento (Nmap) son válidos y se muestran abajo.
                    </div>
                  </div>
                )}

                {/* 4. Área Central - El Núcleo del Proyecto */}
                <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 animate-in fade-in slide-in-from-bottom-4 duration-500 delay-100 fill-mode-both">
                  
                  {/* Consola de Ejecución — stream SSE (HU-020) */}
                  <ScanConsole
                    targetUrl={targetUrl}
                    auditToken={auditToken}
                    isAuditing={isAuditing}
                  />

                  {/* Módulo de correlación de vectores de ataque (motor heurístico, sin LLM) */}
                  <div className="xl:col-span-1 bg-gradient-to-br from-[#1E293B] via-[#141E30] to-[#0B1121] border border-[#D4AF37]/50 rounded-xl overflow-hidden shadow-[0_0_25px_rgba(212,175,55,0.08)] flex flex-col relative min-w-0">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-[#D4AF37]/5 blur-3xl rounded-full pointer-events-none"></div>

                    <div className="px-6 py-4 border-b border-[#D4AF37]/20 flex justify-between items-center bg-[#D4AF37]/10 z-10">
                      <div className="flex items-center gap-3">
                        <div className="p-1.5 bg-[#D4AF37]/20 rounded-md">
                          <Cpu className="w-5 h-5 text-[#D4AF37]" />
                        </div>
                        <h3 className="font-bold text-white text-[15px]">Análisis de Impacto</h3>
                      </div>
                      <span className="text-[10px] bg-[#0B1121] text-[#D4AF37] px-2.5 py-1 rounded border border-[#D4AF37]/30 font-mono font-semibold tracking-wider">
                        {vectorAnalysisMeta?.source === 'llm'
                          ? `IA · ${vectorAnalysisMeta.model_used}`
                          : 'MOTOR HEURÍSTICO'}
                      </span>
                    </div>
                    
                    <div className="p-6 flex-1 overflow-y-auto z-10 relative">
                      {!showInsights ? (
                        <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 animate-pulse">
                          <Cpu className="w-12 h-12 text-[#D4AF37]/30 mb-4" />
                          <p className="text-sm text-center px-4">Esperando resultados del escaneo para generar análisis...</p>
                        </div>
                      ) : (
                        <div className="animate-in fade-in slide-in-from-right-4 duration-700">
                          <h4 className="text-[15px] font-semibold text-white mb-4">Vectores de Ataque Correlacionados</h4>

                          {attackVectors.length === 0 ? (
                            <div className="flex items-start gap-3 bg-slate-800/40 border border-slate-700/50 rounded-lg p-4">
                              <Info className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
                              <p className="text-[13px] text-slate-400 leading-relaxed">
                                Esperando correlación de impacto para este escaneo
                                {lastScanId ? ` (${lastScanId.slice(0, 8)}…)` : ''}.
                                Vuelve a ejecutar la auditoría si el panel sigue vacío.
                              </p>
                            </div>
                          ) : (
                            <>
                              {(() => {
                                const threat = describeThreatLevel(attackVectors);
                                return threat ? (
                                  <div className="mb-6 flex items-center justify-between bg-red-500/10 border border-red-500/20 rounded-lg p-4 shadow-inner">
                                    <span className="text-xs text-slate-300 uppercase tracking-widest font-bold">Nivel de Amenaza Estimado</span>
                                    <div className={`flex items-center gap-2 font-black text-sm tracking-wide ${threat.className}`}>
                                      <AlertTriangle className="w-4 h-4" />
                                      {threat.label}
                                    </div>
                                  </div>
                                ) : null;
                              })()}

                              <div className="space-y-4">
                                {attackVectors.map((vector) => (
                                  <div key={vector.vector_id} className="relative">
                                    <div className="absolute left-0 top-0 bottom-0 w-1 bg-[#D4AF37] rounded-l"></div>
                                    <div className="bg-black/40 pl-5 pr-4 py-3 rounded border border-slate-700/50">
                                      <div className="flex items-center justify-between mb-2 gap-2">
                                        <span className="text-[13px] font-semibold text-white">{vector.name}</span>
                                        <span className="text-[11px] font-bold text-[#D4AF37] shrink-0">Score {vector.severity_score}</span>
                                      </div>
                                      <p className="text-[13px] text-slate-300 leading-relaxed mb-2">{vector.justification}</p>
                                      <p className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Impacto estimado: {vector.estimated_impact}</p>
                                    </div>
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

                {/* 5. Tabla Inferior - Trazabilidad de Hallazgos */}
                <div className="bg-[#1E293B] border border-slate-700 rounded-xl overflow-hidden shadow-lg animate-in fade-in slide-in-from-bottom-4 duration-500 delay-200 fill-mode-both">
                  <div className="px-6 py-5 border-b border-slate-700 bg-[#1E293B] flex items-center justify-between">
                    <h3 className="font-bold text-white text-[15px] flex items-center gap-2">
                      <Database className="w-4 h-4 text-[#7A1C3E]" />
                      Trazabilidad de Hallazgos
                    </h3>
                    <span className="text-xs text-slate-400 font-medium px-3 py-1 bg-slate-800 rounded-full border border-slate-700">
                      {lastScanId
                        ? `${findings.length} hallazgo(s) · scan ${lastScanId.slice(0, 8)}…`
                        : `Mostrando ${findings.length} vulnerabilidad${findings.length !== 1 ? 'es' : ''}`}
                    </span>
                  </div>
                  <div className="overflow-x-auto min-h-[150px]">
                    {findings.length === 0 ? (
                      <div className="flex flex-col items-center justify-center py-12 text-slate-500 px-6 text-center">
                        <History className="w-8 h-8 mb-3 opacity-50" />
                        <p className="text-sm">
                          Aún no hay hallazgos de esta sesión. Ejecuta una auditoría para llenar Trazabilidad e Impacto.
                        </p>
                      </div>
                    ) : (
                      <table className="w-full text-left text-sm animate-in fade-in duration-500">
                        <thead className="bg-[#0B1121] text-xs uppercase text-slate-400 border-b border-slate-700 font-semibold tracking-wider">
                          <tr>
                            <th className="px-6 py-4">ID</th>
                            <th className="px-6 py-4">Vulnerabilidad</th>
                            <th className="px-6 py-4">Vector de Ataque</th>
                            <th className="px-6 py-4">Criticidad</th>
                            <th className="px-6 py-4">Estado de Validación</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/80">
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
            
          </div>
        </div>
      </div>
    </div>
  );
}

/* --- Componentes Auxiliares --- */

const NavItem = ({ icon, label, active, badge, onClick }: { icon: React.ReactElement, label: string, active?: boolean, badge?: string, onClick?: () => void }) => (
  <button onClick={onClick} className={`w-full flex items-center justify-between px-4 py-3 rounded-lg transition-all font-medium ${active ? 'bg-[#7A1C3E] text-white shadow-md shadow-[#7A1C3E]/20' : 'text-slate-400 hover:bg-[#7A1C3E] hover:text-white group'}`}>
    <div className="flex items-center gap-3.5">
      {React.cloneElement(icon, { className: `w-[18px] h-[18px] ${active ? 'text-white' : 'text-slate-500 group-hover:text-white'}` })}
      <span className="text-[13px] text-left">{label}</span>
    </div>
    {badge && (
      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
        active 
          ? 'bg-white/20 text-white border-white/30' 
          : 'bg-[#D4AF37]/10 text-[#D4AF37] border-[#D4AF37]/30 group-hover:bg-white/20 group-hover:text-white group-hover:border-white/30'
      }`}>
        {badge}
      </span>
    )}
  </button>
);

const MetricCard = ({ title, value, module, icon, color, loading }: { title: string, value: string, module: string, icon: React.ReactElement, color: string, loading?: boolean }) => {
  const colorMap: Record<string, string> = {
    blue: 'text-blue-400 bg-blue-500/10 border-blue-500/20 shadow-[0_0_15px_rgba(59,130,246,0.05)]',
    indigo: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.05)]',
    red: 'text-red-400 bg-red-500/10 border-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.05)]',
    gold: 'text-[#D4AF37] bg-[#D4AF37]/10 border-[#D4AF37]/20 shadow-[0_0_15px_rgba(212,175,55,0.05)]',
  };

  return (
    <div className="bg-[#1E293B] border border-slate-700 rounded-xl p-6 shadow-lg transition-transform hover:-translate-y-1 duration-300">
      <div className="flex justify-between items-start">
        <div>
          <p className="text-[13px] text-slate-400 font-semibold mb-2">{title}</p>
          <h3 className="text-3xl font-black text-white tracking-tight">{loading ? '—' : value}</h3>
        </div>
        <div className={`p-3 rounded-xl border ${colorMap[color]}`}>
          {React.cloneElement(icon, { className: 'w-6 h-6' })}
        </div>
      </div>
      <div className="mt-5 pt-4 border-t border-slate-700/50 flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-widest font-bold text-slate-500">{module}</span>
      </div>
    </div>
  );
};

const TableRow = ({ id, name, vector, severity, status }: { id: string, name: string, vector: string, severity: Severity, status: string }) => {
  const getSeverityBadge = (sev: Severity) => {
    switch(sev) {
      case 'Crítico': return <span className="inline-flex items-center px-2.5 py-1 rounded text-[11px] font-bold bg-red-500/10 text-red-500 border border-red-500/30 uppercase tracking-wider">CRÍTICO</span>;
      case 'Alto': return <span className="inline-flex items-center px-2.5 py-1 rounded text-[11px] font-bold bg-orange-500/10 text-orange-400 border border-orange-500/30 uppercase tracking-wider">ALTO</span>;
      case 'Medio': return <span className="inline-flex items-center px-2.5 py-1 rounded text-[11px] font-bold bg-[#D4AF37]/10 text-[#D4AF37] border border-[#D4AF37]/30 uppercase tracking-wider">MEDIO</span>;
      case 'Bajo': return <span className="inline-flex items-center px-2.5 py-1 rounded text-[11px] font-bold bg-sky-500/10 text-sky-400 border border-sky-500/30 uppercase tracking-wider">BAJO</span>;
      case 'Info': return <span className="inline-flex items-center px-2.5 py-1 rounded text-[11px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30 uppercase tracking-wider">INFO</span>;
      case 'Desconocido': return <span className="inline-flex items-center px-2.5 py-1 rounded text-[11px] font-bold bg-slate-500/10 text-slate-400 border border-slate-500/30 uppercase tracking-wider">DESCONOCIDO</span>;
      default: return null;
    }
  };

  const getStatusBadge = (stat: string) => {
    switch(stat) {
      case 'checked': return (
        <div className="flex items-center gap-2 text-green-400 text-[13px] font-medium bg-green-500/5 px-3 py-1.5 rounded-lg border border-green-500/10 w-fit">
          <CheckCircle2 className="w-4 h-4" />
          <span>Confirmado manualmente</span>
        </div>
      );
      case 'unchecked': return (
        <div className="flex items-center gap-2 text-slate-400 text-[13px] font-medium bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700 w-fit">
          <Clock className="w-4 h-4" />
          <span>Pendiente de validación</span>
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
                <span className="text-[#D4AF37] text-sm font-bold flex items-center gap-1">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" /> Escaneando...
                </span>
              ) : primaryHost ? (
                <span className={`text-sm font-bold flex items-center gap-1 ${primaryHost.status === 'up' ? 'text-green-400' : 'text-red-400'}`}>
                  <span className={`w-2 h-2 rounded-full ${primaryHost.status === 'up' ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`}></span>
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
    { label: 'Medio', color: 'text-[#D4AF37]' },
    { label: 'Bajo', color: 'text-sky-400' },
  ];

  return (
    <div className="grid grid-cols-1 gap-6 animate-in fade-in duration-300">
      <div className="bg-[#1E293B] border border-slate-700 rounded-xl p-6 shadow-lg">
        <div className="flex flex-wrap gap-4 justify-between items-end mb-6">
          <div>
            <h3 className="text-white font-bold text-lg flex items-center gap-2 mb-1"><ScanLine className="w-5 h-5 text-emerald-400" /> Resultados de Escaneo (Nuclei)</h3>
            <p className="text-slate-400 text-sm break-all">Plantillas de vulnerabilidad web, CVEs y misconfigurations sobre {targetUrl}.</p>
          </div>
          <div className="text-right">
            <p className="text-3xl font-black text-white">{findings.length}</p>
            <p className="text-xs text-emerald-400 font-bold uppercase tracking-widest">
              {isAuditing ? 'En Curso' : reportStatus}
            </p>
          </div>
        </div>

        {isAuditing && (
          <div className="w-full bg-slate-800 rounded-full h-2 mb-6 overflow-hidden border border-slate-700">
            <div className="bg-emerald-500 h-2 rounded-full relative w-full">
              <div className="absolute top-0 right-0 bottom-0 left-0 bg-[linear-gradient(45deg,rgba(255,255,255,0.15)_25%,transparent_25%,transparent_50%,rgba(255,255,255,0.15)_50%,rgba(255,255,255,0.15)_75%,transparent_75%,transparent)] bg-[length:1rem_1rem] animate-[progress_1s_linear_infinite]"></div>
            </div>
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

      <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex items-start gap-3">
        <Info className="w-4 h-4 text-amber-300 shrink-0 mt-0.5" />
        <p className="text-xs text-amber-200">
          <span className="font-semibold">SQLMap: no implementado.</span> Este backend no tiene integración real con SQLMap —
          esta pestaña solo muestra resultados reales de Nuclei.
        </p>
      </div>
    </div>
  );
};

const MetasploitView = ({ targetUrl }: { targetUrl: string }) => (
  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 lg:h-[500px] animate-in fade-in duration-300">
    <div className="lg:col-span-1 flex flex-col gap-6">
      <div className="bg-[#1E293B] border border-slate-700 rounded-xl p-6 shadow-lg flex-1">
        <h3 className="text-white font-bold flex items-center gap-2 mb-4"><ShieldCheck className="w-5 h-5 text-[#7A1C3E]" /> Sesiones Activas</h3>
        
        <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4 mb-4">
          <div className="flex justify-between items-start mb-2">
            <span className="text-xs text-green-400 font-bold uppercase tracking-widest">Meterpreter 1</span>
            <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
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
          <pre className="text-[#7A1C3E] font-bold">
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
        <div className="mb-1 text-green-400">[+] The target is vulnerable.</div>
        <div className="mb-1 text-slate-400">[*] Executing payload...</div>
        <div className="mb-1 text-green-400">[*] Meterpreter session 1 opened (192.168.1.50:4444 -{'>'} 192.168.1.105:39842) at 2026-06-06 14:04:12</div>
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
          className="w-full bg-[#7A1C3E] hover:bg-[#90244B] text-white py-2 rounded-lg text-sm font-semibold flex items-center justify-center gap-2 mb-6 transition-colors"
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
              <Cpu className="w-10 h-10 text-[#D4AF37]/30 mb-4" />
              <p className="text-sm">
                {findings.length > 0
                  ? `Pregúntale a la IA sobre los ${findings.length} hallazgo(s) del escaneo actual.`
                  : 'Aún no hay hallazgos en esta sesión — igual puedes preguntar lo que quieras.'}
              </p>
            </div>
          ) : (
            messages.map((m, i) => (
              <div key={i} className={`flex gap-4 max-w-3xl ${m.role === 'user' ? '' : 'ml-auto flex-row-reverse'}`}>
                <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${m.role === 'user' ? 'bg-slate-700' : 'bg-[#D4AF37]/20 border border-[#D4AF37]/30'}`}>
                  {m.role === 'user' ? <Lock className="w-4 h-4 text-slate-300" /> : <Cpu className="w-4 h-4 text-[#D4AF37]" />}
                </div>
                <div className={`rounded-2xl p-4 text-sm whitespace-pre-wrap ${m.role === 'user' ? 'bg-slate-800 rounded-tl-none text-slate-200' : 'bg-[#D4AF37]/10 border border-[#D4AF37]/20 rounded-tr-none text-slate-300'}`}>
                  {m.content}
                </div>
              </div>
            ))
          )}
          {sending && (
            <div className="flex gap-4 max-w-3xl ml-auto flex-row-reverse">
              <div className="w-8 h-8 rounded-full bg-[#D4AF37]/20 flex items-center justify-center shrink-0 border border-[#D4AF37]/30">
                <Cpu className="w-4 h-4 text-[#D4AF37]" />
              </div>
              <div className="bg-[#D4AF37]/10 border border-[#D4AF37]/20 rounded-2xl rounded-tr-none p-4 text-sm text-slate-400 flex items-center gap-2">
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
              className="w-full bg-[#0B1121] border border-slate-700 rounded-lg pl-4 pr-12 py-3 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-[#D4AF37]/50 focus:ring-1 focus:ring-[#D4AF37]/50 disabled:opacity-50"
            />
            <button
              onClick={handleSend}
              disabled={sending || !input.trim()}
              className="absolute right-2 top-2 bottom-2 bg-[#D4AF37] hover:bg-[#B3932E] disabled:opacity-50 disabled:cursor-not-allowed text-[#0B1121] p-2 rounded-md transition-colors"
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
                      <span className="text-green-400 flex items-center gap-1"><CheckCircle2 className="w-4 h-4" /> Completado</span>
                    ) : job.status === 'failed' ? (
                      <span className="text-red-400 flex items-center gap-1" title={job.error ?? undefined}><AlertTriangle className="w-4 h-4" /> Error</span>
                    ) : (
                      <span className="text-[#D4AF37] flex items-center gap-1"><Loader2 className="w-4 h-4 animate-spin" /> {job.status === 'running' ? 'En curso' : 'Pendiente'}</span>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    {job.job_type === 'vulnscan' && job.status === 'done' ? (
                      <button
                        onClick={() => handleDownload(job)}
                        disabled={downloadingId === job.id}
                        className="text-[#D4AF37] hover:text-white hover:underline flex items-center gap-1 disabled:opacity-50"
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
