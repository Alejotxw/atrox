import { describe, expect, it } from 'vitest';

import type { HostFinding, Job, VulnFinding } from './api';
import {
  aggregateKpisFromJobs,
  assetsFromJobResult,
  countAssetsAndPorts,
  countCriticalFromFindings,
  pickLatestDone,
} from './dashboardMetrics';

const host = (address: string, ports: number[], status = 'up'): HostFinding => ({
  address,
  status,
  ports: ports.map((port) => ({
    port,
    protocol: 'tcp',
    service: 'http',
    version: '1.0',
  })),
});

const finding = (severity: VulnFinding['severity'], id: string): VulnFinding => ({
  template_id: id,
  name: id,
  severity,
  host: 'http://lab.local',
  matched_at: 'http://lab.local/',
  tags: [],
  description: '',
  references: [],
  extracted_results: [],
  scan_type: 'http',
  ip: '10.0.0.1',
  timestamp: '',
});

function job(partial: Partial<Job> & Pick<Job, 'id' | 'job_type' | 'status'>): Job {
  return {
    params: {},
    result: null,
    error: null,
    created_at: '2026-01-01T00:00:00Z',
    started_at: null,
    finished_at: null,
    ...partial,
  };
}

describe('countAssetsAndPorts', () => {
  it('suma activos y puertos abiertos', () => {
    const counted = countAssetsAndPorts([
      host('10.0.0.1', [80, 443]),
      host('10.0.0.2', [22]),
    ]);
    expect(counted.assets).toBe(2);
    expect(counted.ports).toBe(3);
  });
});

describe('countCriticalFromFindings', () => {
  it('cuenta solo severidad critical', () => {
    expect(
      countCriticalFromFindings([
        finding('critical', 'a'),
        finding('high', 'b'),
        finding('critical', 'c'),
      ]),
    ).toBe(2);
  });
});

describe('pickLatestDone', () => {
  it('elige el discovery done más reciente', () => {
    const jobs = [
      job({
        id: 'old',
        job_type: 'discovery',
        status: 'done',
        finished_at: '2026-01-01T10:00:00Z',
      }),
      job({
        id: 'new',
        job_type: 'discovery',
        status: 'done',
        finished_at: '2026-01-02T10:00:00Z',
      }),
      job({
        id: 'running',
        job_type: 'discovery',
        status: 'running',
        finished_at: null,
      }),
    ];
    expect(pickLatestDone(jobs, 'discovery')?.id).toBe('new');
  });
});

describe('aggregateKpisFromJobs', () => {
  it('agrega KPIs desde jobs discovery + vulnscan', () => {
    const jobs = [
      job({
        id: 'd1',
        job_type: 'discovery',
        status: 'done',
        finished_at: '2026-01-02T00:00:00Z',
        result: {
          hosts: [host('10.0.0.1', [80, 443]), host('10.0.0.2', [3306])],
        },
      }),
      job({
        id: 'v1',
        job_type: 'vulnscan',
        status: 'done',
        finished_at: '2026-01-02T01:00:00Z',
        result: {
          findings: [
            finding('critical', 'c1'),
            finding('medium', 'm1'),
            finding('critical', 'c2'),
          ],
        },
      }),
      job({
        id: 'pending',
        job_type: 'vulnscan',
        status: 'pending',
      }),
    ];

    const kpis = aggregateKpisFromJobs(jobs);
    expect(kpis.assets).toBe(2);
    expect(kpis.ports).toBe(3);
    expect(kpis.criticalVulns).toBe(2);
    expect(kpis.activeScans).toBe(1);
    expect(kpis.sourceScanIds.discovery).toBe('d1');
    expect(kpis.sourceScanIds.vulnscan).toBe('v1');
  });

  it('assetsFromJobResult lee hosts del result', () => {
    expect(
      assetsFromJobResult({
        hosts: [host('1.1.1.1', [53])],
      }),
    ).toHaveLength(1);
    expect(assetsFromJobResult(null)).toEqual([]);
  });
});
