/**
 * Tipos y helpers de la consola en vivo (HU-020).
 */

export type LogSeverity = 'debug' | 'info' | 'warning' | 'error' | 'critical';

export interface ScanLogEvent {
  id: string;
  timestamp: string;
  module: string;
  severity: LogSeverity;
  message: string;
  job_id: string | null;
}

export type ConsoleConnectionStatus = 'connecting' | 'live' | 'reconnecting' | 'error';

export function formatLogTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '--:--:--';
  return date.toTimeString().slice(0, 8);
}

export function moduleColorClass(module: string): string {
  const key = module.toUpperCase();
  if (key === 'NMAP') return 'text-purple-400';
  if (key === 'NUCLEI') return 'text-emerald-400';
  if (key === 'OLLAMA' || key === 'AI') return 'text-[#D4AF37]';
  if (key === 'QUEUE') return 'text-cyan-400';
  if (key === 'ERROR') return 'text-red-400';
  return 'text-blue-400';
}

export function severityBadge(severity: LogSeverity): { label: string; className: string } | null {
  if (severity === 'critical') {
    return { label: 'CRITICAL', className: 'text-red-400 font-bold' };
  }
  if (severity === 'error') {
    return { label: 'ERROR', className: 'text-red-400 font-bold' };
  }
  if (severity === 'warning') {
    return { label: 'WARNING', className: 'text-[#D4AF37] font-bold' };
  }
  return null;
}

export function parseSseDataLine(line: string): ScanLogEvent | null {
  const trimmed = line.trim();
  if (!trimmed.startsWith('data:')) return null;
  const raw = trimmed.slice(5).trim();
  if (!raw || raw === '[DONE]') return null;
  try {
    const parsed = JSON.parse(raw) as ScanLogEvent;
    if (!parsed?.module || !parsed?.message || !parsed?.severity) return null;
    return parsed;
  } catch {
    return null;
  }
}

/** URL del stream SSE (http → EventSource). */
export function consoleStreamUrl(apiBaseUrl: string): string {
  const base = apiBaseUrl.replace(/\/$/, '');
  return `${base}/api/console/stream`;
}
