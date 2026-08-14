import { describe, expect, it } from 'vitest';

import {
  DEFAULT_AUDIT_TASKS,
  countSelectedTasks,
  estimateAuditLabel,
} from './AuditTaskMarker';

describe('AuditTaskMarker helpers', () => {
  it('counts selected tasks', () => {
    expect(countSelectedTasks(DEFAULT_AUDIT_TASKS)).toBe(3);
    expect(countSelectedTasks({ discovery: true, vulnscan: false, vectorAnalysis: false })).toBe(1);
  });

  it('estimates label for full and partial runs', () => {
    expect(estimateAuditLabel(DEFAULT_AUDIT_TASKS)).toMatch(/completa/i);
    expect(
      estimateAuditLabel({ discovery: true, vulnscan: false, vectorAnalysis: false }),
    ).toMatch(/reconocimiento/i);
    expect(
      estimateAuditLabel({ discovery: false, vulnscan: false, vectorAnalysis: false }),
    ).toMatch(/Selecciona/i);
  });
});
