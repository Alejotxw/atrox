import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  FileText,
  Loader2,
  Network,
  RefreshCw,
  Server,
} from 'lucide-react';

import { ApiError } from '../lib/api';
import {
  DASHBOARD_POLL_MS,
  EMPTY_KPIS,
  fetchDashboardKpis,
  type DashboardKpis,
} from '../lib/dashboardMetrics';

const MetricCard = ({
  title,
  value,
  module,
  icon,
  color,
  loading,
}: {
  title: string;
  value: string;
  module: string;
  icon: React.ReactElement;
  color: string;
  loading?: boolean;
}) => {
  const colorMap: Record<string, string> = {
    blue: 'text-blue-400 bg-blue-500/10 border-blue-500/20 shadow-[0_0_15px_rgba(59,130,246,0.05)]',
    indigo:
      'text-indigo-400 bg-indigo-500/10 border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.05)]',
    red: 'text-red-400 bg-red-500/10 border-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.05)]',
    gold: 'text-[#D4AF37] bg-[#D4AF37]/10 border-[#D4AF37]/20 shadow-[0_0_15px_rgba(212,175,55,0.05)]',
  };

  return (
    <div className="bg-[#1E293B] border border-slate-700 rounded-xl p-6 shadow-lg transition-transform hover:-translate-y-1 duration-300 min-w-0">
      <div className="flex justify-between items-start gap-3">
        <div className="min-w-0">
          <p className="text-[13px] text-slate-400 font-semibold mb-2">{title}</p>
          <h3 className="text-3xl font-black text-white tracking-tight truncate">
            {loading ? '—' : value}
          </h3>
        </div>
        <div className={`p-3 rounded-xl border shrink-0 ${colorMap[color]}`}>
          {React.cloneElement(icon, { className: 'w-6 h-6' })}
        </div>
      </div>
      <div className="mt-5 pt-4 border-t border-slate-700/50 flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-widest font-bold text-slate-500">
          {module}
        </span>
      </div>
    </div>
  );
};

/**
 * Panel de KPIs del dashboard (HU-019).
 * Consume HU-010 vía getScanDetail + listJobs; polling sin recarga de página.
 */
export default function DashboardMetricsPanel() {
  const [kpis, setKpis] = useState<DashboardKpis>(EMPTY_KPIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const inFlight = useRef(false);

  const load = useCallback(async (isPoll = false) => {
    if (inFlight.current) return;
    if (document.visibilityState === 'hidden') return;

    inFlight.current = true;
    if (isPoll) setRefreshing(true);
    else setLoading(true);

    try {
      const next = await fetchDashboardKpis();
      setKpis(next);
      setError(null);
    } catch (err) {
      const message =
        err instanceof ApiError
          ? `Backend ${err.status}: no se pudieron cargar métricas`
          : 'No se pudo conectar con el backend';
      setError(message);
    } finally {
      inFlight.current = false;
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load(false);
    const id = window.setInterval(() => load(true), DASHBOARD_POLL_MS);

    const onVisibility = () => {
      if (document.visibilityState === 'visible') load(true);
    };
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      window.clearInterval(id);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [load]);

  const lastLabel = kpis.lastUpdated
    ? new Date(kpis.lastUpdated).toLocaleTimeString()
    : '—';

  return (
    <section className="space-y-3 animate-in fade-in duration-300" aria-label="KPIs de seguridad">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-bold text-white tracking-wide">
            Riesgo global — KPIs en vivo
          </h2>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Fuente: HU-010 · actualización cada {DASHBOARD_POLL_MS / 1000}s · última:{' '}
            {lastLabel}
          </p>
        </div>
        <button
          type="button"
          onClick={() => load(true)}
          disabled={refreshing || loading}
          className="inline-flex items-center gap-2 text-xs font-semibold text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-600 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
        >
          {refreshing || loading ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
          ) : (
            <RefreshCw className="w-3.5 h-3.5" />
          )}
          Actualizar
        </button>
      </div>

      {error && (
        <div className="text-xs text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-lg px-4 py-2">
          {error}. Se muestran últimos valores conocidos o ceros.
        </div>
      )}

      {/* Responsive desktop: 1 → 2 → 4 columnas */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
        <MetricCard
          title="Activos Descubiertos"
          value={String(kpis.assets)}
          module="HU-010 · Discovery"
          icon={<Network />}
          color="blue"
          loading={loading}
        />
        <MetricCard
          title="Puertos y Servicios"
          value={String(kpis.ports)}
          module="HU-010 · Nmap"
          icon={<Server />}
          color="indigo"
          loading={loading}
        />
        <MetricCard
          title="Vulnerabilidades Críticas"
          value={String(kpis.criticalVulns)}
          module="HU-010 · Nuclei"
          icon={<AlertTriangle />}
          color="red"
          loading={loading}
        />
        <MetricCard
          title="Escaneos Activos"
          value={String(kpis.activeScans)}
          module="Cola de trabajos"
          icon={<FileText />}
          color="gold"
          loading={loading}
        />
      </div>
    </section>
  );
}
