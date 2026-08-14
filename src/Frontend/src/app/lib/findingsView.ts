/**
 * Lógica pura de la vista de gestión de hallazgos (HU-021): combina hallazgos
 * (HU-010), score de confianza (HU-016) y vector de ataque correlacionado
 * (HU-014) en filas de tabla, y aplica los filtros de confianza/falso
 * positivo (el filtro de severidad va server-side, vía HU-010).
 *
 * Separado del componente React para poder testear la lógica de negocio sin
 * montar DOM.
 */
import type { AttackVector, ConfidenceScoreResult, VulnFinding } from './api';

// Debe coincidir con MAX_BATCH_SIZE de atrox/ai/agents/vectors/analyzer.py:
// POST /api/ai/vectors/analyze trunca silenciosamente a 10 hallazgos por
// llamada, así que agrupamos en lotes de ese tamaño para no perder vectores
// en páginas con page_size > 10.
export const VECTORS_BATCH_SIZE = 10;

const SEVERITY_RANK: Record<VulnFinding['severity'], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  unknown: 5,
};

/** Prioriza criticidad y recorta el lote enviado al análisis IA (menos carga). */
export function prioritizeFindingsForAi(
  findings: VulnFinding[],
  limit: number = VECTORS_BATCH_SIZE,
): VulnFinding[] {
  return [...findings]
    .sort((a, b) => {
      const bySev = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
      if (bySev !== 0) return bySev;
      return a.template_id.localeCompare(b.template_id);
    })
    .slice(0, Math.max(0, limit));
}

export function chunk<T>(items: T[], size: number): T[][] {
  if (size <= 0) return [items];
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}

/** El finding_id usado por HU-014/HU-016 por defecto es el template_id del hallazgo. */
export function findingId(finding: VulnFinding): string {
  return finding.template_id;
}

/** Primer vector correlacionado (la lista ya viene ordenada por impacto desde el backend) que referencia este hallazgo. */
export function matchVectorForFinding(
  vectors: AttackVector[],
  id: string,
): AttackVector | undefined {
  return vectors.find((vector) => vector.finding_ids.includes(id));
}

export type EstadoLabel = 'Válido' | 'Probable Falso Positivo';

export function deriveEstado(score: ConfidenceScoreResult | undefined): EstadoLabel | 'Sin evaluar' {
  if (!score) return 'Sin evaluar';
  return score.probable_fp ? 'Probable Falso Positivo' : 'Válido';
}

export interface FindingRow {
  finding: VulnFinding;
  findingId: string;
  score?: ConfidenceScoreResult;
  vector?: AttackVector;
}

export function buildFindingRows(
  findings: VulnFinding[],
  scores: ConfidenceScoreResult[],
  vectors: AttackVector[],
): FindingRow[] {
  const scoreById = new Map(scores.map((s) => [s.finding_id, s]));

  return findings.map((finding) => {
    const id = findingId(finding);
    return {
      finding,
      findingId: id,
      score: scoreById.get(id),
      vector: matchVectorForFinding(vectors, id),
    };
  });
}

export type FalsePositiveFilter = 'all' | 'valid' | 'probable_fp';

export interface FindingsFilters {
  minScore: number;
  falsePositive: FalsePositiveFilter;
}

export const DEFAULT_FILTERS: FindingsFilters = { minScore: 0, falsePositive: 'all' };

export function filterRows(rows: FindingRow[], filters: FindingsFilters): FindingRow[] {
  return rows.filter((row) => {
    if (!row.score) return true; // aún no evaluado — no se oculta, se muestra "Sin evaluar"

    if (row.score.score < filters.minScore) return false;

    if (filters.falsePositive === 'valid' && row.score.probable_fp) return false;
    if (filters.falsePositive === 'probable_fp' && !row.score.probable_fp) return false;

    return true;
  });
}
