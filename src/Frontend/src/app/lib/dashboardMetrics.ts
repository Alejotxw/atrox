/**
 * Agregación de KPIs de seguridad para el dashboard (HU-019).
 * Funciones puras + fetch — testeable sin DOM.
 */

import {
  getScanDetail,
  listJobs,
  type HostFinding,
  type Job,
  type VulnFinding,
} from './api';

export interface DashboardKpis {
  assets: number;
  ports: number;
  criticalVulns: number;
  activeScans: number;
  lastUpdated: string | null;
  sourceScanIds: {
    discovery: string | null;
    vulnscan: string | null;
  };
}

export const EMPTY_KPIS: DashboardKpis = {
  assets: 0,
  ports: 0,
  criticalVulns: 0,
  activeScans: 0,
  lastUpdated: null,
  sourceScanIds: { discovery: null, vulnscan: null },
};

/** Intervalo de polling sin recarga completa (ms). */
export const DASHBOARD_POLL_MS = 5000;

function isDone(job: Job): boolean {
  return job.status === 'done';
}

function byNewest(a: Job, b: Job): number {
  const ta = a.finished_at ?? a.created_at;
  const tb = b.finished_at ?? b.created_at;
  return tb.localeCompare(ta);
}

export function pickLatestDone(jobs: Job[], type: Job['job_type']): Job | null {
  const matches = jobs.filter((j) => j.job_type === type && isDone(j));
  if (matches.length === 0) return null;
  return [...matches].sort(byNewest)[0];
}

export function countAssetsAndPorts(assets: HostFinding[]): {
  assets: number;
  ports: number;
} {
  const upHosts = assets.filter((h) => h.status === 'up' || h.ports?.length > 0);
  const ports = assets.reduce((sum, host) => sum + (host.ports?.length ?? 0), 0);
  return {
    assets: upHosts.length > 0 ? upHosts.length : assets.length,
    ports,
  };
}

export function countCriticalFromFindings(findings: VulnFinding[]): number {
  return findings.filter((f) => f.severity === 'critical').length;
}

/**
 * Extrae hosts/ports del result crudo de un job discovery (fallback sin HU-010).
 */
export function assetsFromJobResult(result: Record<string, unknown> | null): HostFinding[] {
  if (!result) return [];
  const hosts = result.hosts;
  if (!Array.isArray(hosts)) return [];
  return hosts as HostFinding[];
}

/**
 * Extrae findings del result crudo de un job vulnscan (fallback).
 */
export function findingsFromJobResult(result: Record<string, unknown> | null): VulnFinding[] {
  if (!result) return [];
  const findings = result.findings;
  if (!Array.isArray(findings)) return [];
  return findings as VulnFinding[];
}

export function aggregateKpisFromJobs(jobs: Job[]): DashboardKpis {
  const discovery = pickLatestDone(jobs, 'discovery');
  const vulnscan = pickLatestDone(jobs, 'vulnscan');

  const fromDiscovery = countAssetsAndPorts(assetsFromJobResult(discovery?.result ?? null));
  const criticalVulns = countCriticalFromFindings(
    findingsFromJobResult(vulnscan?.result ?? null),
  );
  const activeScans = jobs.filter(
    (j) => j.status === 'pending' || j.status === 'running',
  ).length;

  return {
    assets: fromDiscovery.assets,
    ports: fromDiscovery.ports,
    criticalVulns,
    activeScans,
    lastUpdated: new Date().toISOString(),
    sourceScanIds: {
      discovery: discovery?.id ?? null,
      vulnscan: vulnscan?.id ?? null,
    },
  };
}

/**
 * Carga KPIs: lista jobs y enriquece con HU-010 (GET /api/scans/{id}).
 * Prioriza totales de ScanDetailResponse; si falla, usa result del job.
 */
export async function fetchDashboardKpis(): Promise<DashboardKpis> {
  const jobs = await listJobs();
  const base = aggregateKpisFromJobs(jobs);
  let assets = base.assets;
  let ports = base.ports;
  let criticalVulns = base.criticalVulns;

  if (base.sourceScanIds.discovery) {
    try {
      const detail = await getScanDetail(base.sourceScanIds.discovery, { pageSize: 1 });
      if (detail.assets?.length) {
        const counted = countAssetsAndPorts(detail.assets);
        assets = counted.assets;
        ports = counted.ports;
      }
    } catch {
      // Mantener fallback del job.result
    }
  }

  if (base.sourceScanIds.vulnscan) {
    try {
      const detail = await getScanDetail(base.sourceScanIds.vulnscan, {
        severity: 'critical',
        pageSize: 1,
      });
      criticalVulns = detail.findings?.total ?? criticalVulns;
    } catch {
      // Mantener fallback
    }
  }

  return {
    ...base,
    assets,
    ports,
    criticalVulns,
    lastUpdated: new Date().toISOString(),
  };
}
