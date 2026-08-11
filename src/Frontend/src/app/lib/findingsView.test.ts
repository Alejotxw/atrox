import { describe, expect, it } from 'vitest';

import type { AttackVector, ConfidenceScoreResult, VulnFinding } from './api';
import {
  buildFindingRows,
  chunk,
  deriveEstado,
  filterRows,
  findingId,
  matchVectorForFinding,
  prioritizeFindingsForAi,
} from './findingsView';

function makeFinding(overrides: Partial<VulnFinding> = {}): VulnFinding {
  return {
    template_id: 'generic-detect',
    name: 'Generic Finding',
    severity: 'medium',
    host: 'http://example.com',
    matched_at: 'http://example.com/',
    tags: [],
    description: '',
    references: [],
    extracted_results: [],
    scan_type: 'http',
    ip: '',
    timestamp: '',
    ...overrides,
  };
}

function makeScore(overrides: Partial<ConfidenceScoreResult> = {}): ConfidenceScoreResult {
  return {
    finding_id: 'generic-detect',
    score: 50,
    threshold: 40,
    probable_fp: false,
    explanation: 'severidad medium (base 50) -> score 50/100 (umbral 40)',
    generation_time_ms: 0.1,
    within_sla: true,
    ...overrides,
  };
}

function makeVector(overrides: Partial<AttackVector> = {}): AttackVector {
  return {
    rank: 1,
    vector_id: 'standalone:generic-detect',
    name: 'Explotación directa: Generic Finding',
    severity_score: 5,
    finding_ids: ['generic-detect'],
    chain: ['paso 1'],
    justification: 'justificación',
    estimated_impact: 'medio',
    ...overrides,
  };
}

describe('chunk', () => {
  it('splits an array into groups of the given size', () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
  });

  it('returns a single chunk when size >= length', () => {
    expect(chunk([1, 2], 10)).toEqual([[1, 2]]);
  });

  it('returns an empty array for empty input', () => {
    expect(chunk([], 10)).toEqual([]);
  });
});

describe('prioritizeFindingsForAi', () => {
  it('orders by severity and respects limit', () => {
    const items = [
      makeFinding({ template_id: 'low', severity: 'low' }),
      makeFinding({ template_id: 'crit', severity: 'critical' }),
      makeFinding({ template_id: 'info', severity: 'info' }),
    ];
    expect(prioritizeFindingsForAi(items, 2).map((f) => f.template_id)).toEqual([
      'crit',
      'low',
    ]);
  });
});

describe('findingId', () => {
  it('uses template_id as the finding identifier', () => {
    expect(findingId(makeFinding({ template_id: 'cve-2021-41773' }))).toBe('cve-2021-41773');
  });
});

describe('matchVectorForFinding', () => {
  it('returns the first vector referencing the finding id', () => {
    const vectors = [
      makeVector({ vector_id: 'a', finding_ids: ['other-id'] }),
      makeVector({ vector_id: 'b', finding_ids: ['target-id', 'other-id'] }),
    ];

    const match = matchVectorForFinding(vectors, 'target-id');

    expect(match?.vector_id).toBe('b');
  });

  it('returns undefined when no vector references the finding', () => {
    const vectors = [makeVector({ finding_ids: ['other-id'] })];

    expect(matchVectorForFinding(vectors, 'missing-id')).toBeUndefined();
  });
});

describe('deriveEstado', () => {
  it('returns "Sin evaluar" when there is no score yet', () => {
    expect(deriveEstado(undefined)).toBe('Sin evaluar');
  });

  it('returns "Válido" when probable_fp is false', () => {
    expect(deriveEstado(makeScore({ probable_fp: false }))).toBe('Válido');
  });

  it('returns "Probable Falso Positivo" when probable_fp is true', () => {
    expect(deriveEstado(makeScore({ probable_fp: true }))).toBe('Probable Falso Positivo');
  });
});

describe('buildFindingRows', () => {
  it('merges findings with their matching score and vector by finding_id', () => {
    const findings = [
      makeFinding({ template_id: 'a' }),
      makeFinding({ template_id: 'b' }),
    ];
    const scores = [makeScore({ finding_id: 'a', score: 90 })];
    const vectors = [makeVector({ finding_ids: ['b'] })];

    const rows = buildFindingRows(findings, scores, vectors);

    expect(rows).toHaveLength(2);
    expect(rows[0].findingId).toBe('a');
    expect(rows[0].score?.score).toBe(90);
    expect(rows[0].vector).toBeUndefined();
    expect(rows[1].findingId).toBe('b');
    expect(rows[1].score).toBeUndefined();
    expect(rows[1].vector?.finding_ids).toContain('b');
  });
});

describe('filterRows', () => {
  const rows = [
    { finding: makeFinding({ template_id: 'high' }), findingId: 'high', score: makeScore({ finding_id: 'high', score: 90, probable_fp: false }) },
    { finding: makeFinding({ template_id: 'low' }), findingId: 'low', score: makeScore({ finding_id: 'low', score: 5, probable_fp: true }) },
    { finding: makeFinding({ template_id: 'pending' }), findingId: 'pending', score: undefined },
  ];

  it('keeps rows without a score regardless of filters (still loading)', () => {
    const result = filterRows(rows, { minScore: 50, falsePositive: 'valid' });
    expect(result.some((r) => r.findingId === 'pending')).toBe(true);
  });

  it('excludes rows below the minimum score', () => {
    const result = filterRows(rows, { minScore: 50, falsePositive: 'all' });
    expect(result.map((r) => r.findingId)).not.toContain('low');
    expect(result.map((r) => r.findingId)).toContain('high');
  });

  it('filters to only valid findings when falsePositive="valid"', () => {
    const result = filterRows(rows, { minScore: 0, falsePositive: 'valid' });
    expect(result.map((r) => r.findingId)).not.toContain('low');
  });

  it('filters to only probable false positives when falsePositive="probable_fp"', () => {
    const result = filterRows(rows, { minScore: 0, falsePositive: 'probable_fp' });
    expect(result.map((r) => r.findingId)).not.toContain('high');
  });
});
