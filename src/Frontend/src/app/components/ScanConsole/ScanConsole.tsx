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
  /** Cuando cambia (nueva auditoría real), limpia la pantalla de la consola. */
  auditToken?: number;
  isAuditing?: boolean;
}

function statusLabel(status: ConsoleConnectionStatus): { text: string; className: string } {
  if (status === 'live') return { text: 'SSE live', className: 'text-emerald-400' };
  if (status === 'reconnecting') return { text: 'Reconectando…', className: 'text-amber-400' };
  if (status === 'error') return { text: 'SSE error', className: 'text-red-400' };
  return { text: 'Conectando…', className: 'text-slate-400' };
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
  const containerRef = useRef<HTMLDivElement>(null);

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

  // Limpia la pantalla al iniciar una auditoría nueva; los eventos reales
  // (encolado/iniciado/completado/fallido + detalle de Nmap/Nuclei) llegan
  // solos por el stream SSE en cuanto el job real se procesa — no hay nada
  // que "disparar" desde el frontend.
  useEffect(() => {
    if (!auditToken) return;
    setLogs([]);
  }, [auditToken]);

  const conn = statusLabel(status);

  return (
    <div className="xl:col-span-2 bg-[#000000] border border-slate-800 rounded-xl overflow-hidden flex flex-col shadow-2xl relative min-w-0">
      <div className="absolute inset-0 bg-gradient-to-b from-transparent to-black/20 pointer-events-none" />
      <div className="bg-[#1E293B] px-5 py-3 border-b border-slate-800 flex items-center justify-between z-10 gap-3 flex-wrap">
        <div className="flex items-center gap-2.5 min-w-0">
          <TerminalSquare className="w-4 h-4 text-slate-400 shrink-0" />
          <span className="text-xs font-mono text-slate-300 font-semibold tracking-wide truncate">
            Consola de Ejecución UNIX
          </span>
          <span className={`text-[10px] font-mono ${conn.className}`}>{conn.text}</span>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400 cursor-pointer select-none">
            <input
              type="checkbox"
              className="rounded border-slate-600 bg-slate-900"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
            />
            Auto-scroll
          </label>
          <div className="flex gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500/90 shadow-[0_0_5px_rgba(239,68,68,0.5)]" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/90 shadow-[0_0_5px_rgba(234,179,8,0.5)]" />
            <div className="w-3 h-3 rounded-full bg-green-500/90 shadow-[0_0_5px_rgba(34,197,94,0.5)]" />
          </div>
        </div>
      </div>
      <div
        ref={containerRef}
        className="p-4 sm:p-6 font-mono text-[13px] text-slate-300 leading-relaxed overflow-y-auto h-[280px] sm:h-[420px] space-y-3 z-10 scroll-smooth"
      >
        <div className="text-slate-500">
          root@ai-pentest:~# ./run_audit.sh --target {targetUrl}
        </div>
        {logs.map((log) => {
          const badge = severityBadge(log.severity);
          return (
            <div
              key={log.id}
              className="text-slate-500 py-0.5 animate-in fade-in slide-in-from-bottom-2 duration-300"
            >
              [{formatLogTime(log.timestamp)}]{' '}
              <span className={`${moduleColorClass(log.module)} font-semibold`}>
                [{log.module}]
              </span>{' '}
              {badge && <span className={badge.className}>[{badge.label}] </span>}
              {log.message}
            </div>
          );
        })}
        {isAuditing && (
          <div className="flex items-center gap-2 mt-3">
            <span className="text-green-400">root@ai-pentest:~#</span>
            <span className="w-2.5 h-4 bg-slate-300 animate-pulse" />
          </div>
        )}
        <div ref={logsEndRef} />
      </div>
    </div>
  );
}
