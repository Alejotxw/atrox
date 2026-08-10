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
  if (key === 'NMAP') return 'text-[#9db0ff]';
  if (key === 'NUCLEI') return 'text-[#c5cedd]';
  if (key === 'OLLAMA' || key === 'AI') return 'text-[#7ea0ff]';
  if (key === 'QUEUE') return 'text-[#8b95a8]';
  if (key === 'ERROR') return 'text-[#e07a7a]';
  return 'text-[#7ea0ff]';
}

export function severityBadge(severity: LogSeverity): { label: string; className: string } | null {
  if (severity === 'critical') {
    return { label: 'CRITICAL', className: 'text-[#e07a7a] font-bold' };
  }
  if (severity === 'error') {
    return { label: 'ERROR', className: 'text-[#e07a7a] font-bold' };
  }
  if (severity === 'warning') {
    return { label: 'WARNING', className: 'text-[#e0a85c] font-bold' };
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
