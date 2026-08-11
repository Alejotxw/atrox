import { useEffect, useRef, useState } from 'react';
import { TerminalSquare } from 'lucide-react';

import {
  formatLogTime,
  moduleColorClass,
  severityBadge,
  type ConsoleConnectionStatus,
  type ScanLogEvent,
} from '../../lib/scanConsole';
import { connectScanConsoleStream } from '../../lib/scanConsoleStream';

const API_BASE_URL: string =
  (import.meta as any).env?.VITE_API_BASE_URL ?? 'http://localhost:8000';

const MAX_LINES = 500;

export interface ScanConsoleProps {
  targetUrl: string;
  auditToken?: number;
  isAuditing?: boolean;
}

function statusLabel(status: ConsoleConnectionStatus): { text: string; className: string } {
  if (status === 'live') return { text: 'SSE live', className: 'text-[var(--ax-info)]' };
  if (status === 'reconnecting') return { text: 'Reconectando…', className: 'text-[var(--ax-warn)]' };
  if (status === 'error') return { text: 'SSE error', className: 'text-[var(--ax-danger)]' };
  return { text: 'Conectando…', className: 'text-[var(--ax-muted)]' };
}

export default function ScanConsole({
  targetUrl,
  auditToken = 0,
  isAuditing = false,
}: ScanConsoleProps) {
  const [logs, setLogs] = useState<ScanLogEvent[]>([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const [status, setStatus] = useState<ConsoleConnectionStatus>('connecting');
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handle = connectScanConsoleStream({
      apiBaseUrl: API_BASE_URL,
      onStatus: setStatus,
      onEvent: (event) => {
        setLogs((prev) => {
          if (prev.some((line) => line.id === event.id)) return prev;
          const next = [...prev, event];
          return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next;
        });
      },
    });
    return () => handle.close();
  }, []);

  useEffect(() => {
    if (!autoScroll) return;
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs, autoScroll]);

  useEffect(() => {
    if (!auditToken) return;
    setLogs([]);
  }, [auditToken]);

  const conn = statusLabel(status);

  return (
    <div className="atrox-panel overflow-hidden flex flex-col relative min-w-0 min-h-[360px]">
      <div className="atrox-panel-head z-10 gap-3 flex-wrap">
        <div className="flex items-center gap-2.5 min-w-0">
          <TerminalSquare className="w-4 h-4 text-[var(--ax-muted)] shrink-0" />
          <span className="text-[13px] text-[var(--ax-text)] font-semibold truncate">
            Consola de ejecución
          </span>
          <span className={`text-[10px] font-mono ${conn.className}`}>{conn.text}</span>
        </div>
        <label className="flex items-center gap-1.5 text-[10px] font-mono text-[var(--ax-muted)] cursor-pointer select-none">
          <input
            type="checkbox"
            className="rounded border-[var(--ax-border)] bg-transparent"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
          />
          Auto-scroll
        </label>
      </div>
      <div className="p-4 font-mono text-[12px] text-[var(--ax-muted)] leading-relaxed overflow-y-auto flex-1 h-[260px] sm:h-[320px] space-y-2 bg-[var(--ax-bg)]">
        <div className="text-[var(--ax-muted)]">
          root@atrox:~# ./run_audit.sh --target {targetUrl}
        </div>
        {logs.map((log) => {
          const badge = severityBadge(log.severity);
          return (
            <div key={log.id} className="text-[var(--ax-muted)]">
              [{formatLogTime(log.timestamp)}]{' '}
              <span className={`${moduleColorClass(log.module)} font-semibold`}>
                [{log.module}]
              </span>{' '}
              {badge && <span className={badge.className}>[{badge.label}] </span>}
              <span className="text-[var(--ax-text)]/85">{log.message}</span>
            </div>
          );
        })}
        {isAuditing && (
          <div className="flex items-center gap-2 mt-2">
            <span className="text-[var(--ax-accent)]">root@atrox:~#</span>
            <span className="w-2 h-4 bg-[var(--ax-text)]/70 animate-pulse" />
          </div>
        )}
        <div ref={logsEndRef} />
      </div>
    </div>
  );
}
