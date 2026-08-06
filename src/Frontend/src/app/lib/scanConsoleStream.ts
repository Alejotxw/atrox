/**
 * Cliente SSE con reconexión automática (HU-020 DoD).
 */

import {
  consoleStreamUrl,
  parseSseDataLine,
  type ConsoleConnectionStatus,
  type ScanLogEvent,
} from './scanConsole';

export interface ScanConsoleStreamOptions {
  apiBaseUrl: string;
  onEvent: (event: ScanLogEvent) => void;
  onStatus?: (status: ConsoleConnectionStatus) => void;
  /** Delay base de reconexión en ms (backoff lineal hasta max). */
  reconnectDelayMs?: number;
  maxReconnectDelayMs?: number;
}

export interface ScanConsoleStreamHandle {
  close: () => void;
}

/**
 * Abre EventSource hacia /api/console/stream.
 * Si la conexión cae, reintenta con backoff (EventSource nativo también reintenta;
 * además recreamos el socket tras error explícito).
 */
export function connectScanConsoleStream(
  options: ScanConsoleStreamOptions,
): ScanConsoleStreamHandle {
  const reconnectDelayMs = options.reconnectDelayMs ?? 1000;
  const maxReconnectDelayMs = options.maxReconnectDelayMs ?? 8000;
  let closed = false;
  let attempt = 0;
  let source: EventSource | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const setStatus = (status: ConsoleConnectionStatus) => {
    options.onStatus?.(status);
  };

  const clearTimer = () => {
    if (timer != null) {
      clearTimeout(timer);
      timer = null;
    }
  };

  const scheduleReconnect = () => {
    if (closed) return;
    setStatus(attempt === 0 ? 'reconnecting' : 'reconnecting');
    const delay = Math.min(reconnectDelayMs * (attempt + 1), maxReconnectDelayMs);
    attempt += 1;
    clearTimer();
    timer = setTimeout(open, delay);
  };

  const open = () => {
    if (closed) return;
    clearTimer();
    if (source) {
      source.close();
      source = null;
    }
    setStatus(attempt === 0 ? 'connecting' : 'reconnecting');
    const url = consoleStreamUrl(options.apiBaseUrl);
    source = new EventSource(url);

    source.onopen = () => {
      attempt = 0;
      setStatus('live');
    };

    source.onmessage = (msg) => {
      const event = parseSseDataLine(`data: ${msg.data}`);
      if (event) options.onEvent(event);
    };

    source.onerror = () => {
      if (closed) return;
      setStatus('error');
      source?.close();
      source = null;
      scheduleReconnect();
    };
  };

  open();

  return {
    close: () => {
      closed = true;
      clearTimer();
      source?.close();
      source = null;
    },
  };
}
