import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

import {
  consoleStreamUrl,
  formatLogTime,
  moduleColorClass,
  parseSseDataLine,
  severityBadge,
} from './scanConsole';
import { connectScanConsoleStream } from './scanConsoleStream';

describe('scanConsole helpers', () => {
  it('formats timestamp to HH:MM:SS', () => {
    const iso = '2026-08-02T20:15:33.000Z';
    const formatted = formatLogTime(iso);
    expect(formatted).toMatch(/^\d{2}:\d{2}:\d{2}$/);
  });

  it('parses SSE data lines with module and severity', () => {
    const event = parseSseDataLine(
      'data: {"id":"1","timestamp":"2026-08-02T20:00:00Z","module":"NMAP","severity":"info","message":"up","job_id":null}',
    );
    expect(event?.module).toBe('NMAP');
    expect(event?.severity).toBe('info');
    expect(event?.message).toBe('up');
  });

  it('ignores keepalive and garbage', () => {
    expect(parseSseDataLine(': keepalive')).toBeNull();
    expect(parseSseDataLine('data: not-json')).toBeNull();
  });

  it('maps module colors and severity badges', () => {
    expect(moduleColorClass('NUCLEI')).toContain('emerald');
    expect(severityBadge('critical')?.label).toBe('CRITICAL');
    expect(severityBadge('info')).toBeNull();
  });

  it('builds stream url', () => {
    expect(consoleStreamUrl('http://localhost:8000/')).toBe(
      'http://localhost:8000/api/console/stream',
    );
  });
});

describe('connectScanConsoleStream reconnect', () => {
  class FakeEventSource {
    static instances: FakeEventSource[] = [];
    url: string;
    onopen: ((ev: Event) => void) | null = null;
    onmessage: ((ev: MessageEvent) => void) | null = null;
    onerror: ((ev: Event) => void) | null = null;
    closed = false;

    constructor(url: string) {
      this.url = url;
      FakeEventSource.instances.push(this);
    }

    close() {
      this.closed = true;
    }
  }

  beforeEach(() => {
    FakeEventSource.instances = [];
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('recrea EventSource tras error', () => {
    const onEvent = vi.fn();
    const onStatus = vi.fn();
    const handle = connectScanConsoleStream({
      apiBaseUrl: 'http://localhost:8000',
      onEvent,
      onStatus,
      reconnectDelayMs: 100,
      maxReconnectDelayMs: 100,
    });

    expect(FakeEventSource.instances).toHaveLength(1);
    FakeEventSource.instances[0].onopen?.(new Event('open'));
    expect(onStatus).toHaveBeenCalledWith('live');

    FakeEventSource.instances[0].onerror?.(new Event('error'));
    expect(onStatus).toHaveBeenCalledWith('error');

    vi.advanceTimersByTime(100);
    expect(FakeEventSource.instances.length).toBeGreaterThanOrEqual(2);

    handle.close();
  });
});
