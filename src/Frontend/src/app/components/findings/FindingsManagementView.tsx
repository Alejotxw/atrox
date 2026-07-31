import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Loader2,
  ShieldOff,
  ShieldQuestion,
} from 'lucide-react';

import {
  ApiError,
  analyzeVectors,
  getScanDetail,
  markFalsePositive,
  scoreFinding,
  type AttackVector,
  type ConfidenceScoreResult,
  type ScanDetailResponse,
  type VulnSeverity,
} from '../../lib/api';
import {
  DEFAULT_FILTERS,
  VECTORS_BATCH_SIZE,
  buildFindingRows,
  chunk,
  deriveEstado,
  filterRows,
  type FalsePositiveFilter,
  type FindingRow,
} from '../../lib/findingsView';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../ui/table';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../ui/select';

const SEVERITY_OPTIONS: { value: VulnSeverity | 'all'; label: string }[] = [
  { value: 'all', label: 'Todas las severidades' },
  { value: 'critical', label: 'Crítica' },
  { value: 'high', label: 'Alta' },
  { value: 'medium', label: 'Media' },
  { value: 'low', label: 'Baja' },
  { value: 'info', label: 'Informativa' },
];

const CONFIDENCE_OPTIONS = [
  { value: 0, label: 'Cualquier confianza' },
  { value: 25, label: 'Score ≥ 25' },
  { value: 50, label: 'Score ≥ 50' },
  { value: 75, label: 'Score ≥ 75' },
];

const FP_OPTIONS: { value: FalsePositiveFilter; label: string }[] = [
  { value: 'all', label: 'Todos los estados' },
  { value: 'valid', label: 'Solo válidos' },
  { value: 'probable_fp', label: 'Solo probables falsos positivos' },
];

function severityBadgeVariant(
  severity: VulnSeverity,
): 'destructive' | 'default' | 'secondary' | 'outline' {
  if (severity === 'critical' || severity === 'high') return 'destructive';
  if (severity === 'medium') return 'default';
  return 'secondary';
}

const PAGE_SIZE = VECTORS_BATCH_SIZE;

// No hay login/autenticación en el frontend todavía (ver App.tsx: el
// sidebar muestra "Admin SecOps" hardcodeado como usuario de sesión). Se
// reutiliza el mismo valor como X-Atrox-User al marcar falsos positivos en
// vez de introducir un flujo de identidad nuevo, fuera del alcance de HU-022.
const CURRENT_USER = 'Admin SecOps';

export default function FindingsManagementView() {
  const [scanIdInput, setScanIdInput] = useState('');
  const [scanId, setScanId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<VulnSeverity | 'all'>('all');
  const [page, setPage] = useState(1);
  const [minScore, setMinScore] = useState(DEFAULT_FILTERS.minScore);
  const [fpFilter, setFpFilter] = useState<FalsePositiveFilter>(DEFAULT_FILTERS.falsePositive);

  const [scanDetail, setScanDetail] = useState<ScanDetailResponse | null>(null);
  const [scores, setScores] = useState<ConfidenceScoreResult[]>([]);
  const [vectors, setVectors] = useState<AttackVector[]>([]);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [markingIds, setMarkingIds] = useState<Set<string>>(new Set());
  const [markError, setMarkError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;

    let cancelled = false;

    async function loadFindings() {
      setLoading(true);
      setError(null);

      try {
        const detail = await getScanDetail(scanId as string, {
          severity: severityFilter === 'all' ? undefined : severityFilter,
          page,
          pageSize: PAGE_SIZE,
        });
        if (cancelled) return;
        setScanDetail(detail);

        const findings = detail.findings.items;
        if (findings.length === 0) {
          setScores([]);
          setVectors([]);
          return;
        }

        // HU-016 no tiene endpoint batch: un POST por hallazgo de la página actual.
        const scorePromise = Promise.all(findings.map((finding) => scoreFinding(finding)));
        // HU-014 trunca a VECTORS_BATCH_SIZE por llamada: agrupamos para no perder vectores.
        const vectorPromise = Promise.all(
          chunk(findings, VECTORS_BATCH_SIZE).map((batch) => analyzeVectors(batch)),
        );

        const [scoreResults, vectorBatches] = await Promise.all([scorePromise, vectorPromise]);
        if (cancelled) return;

        setScores(scoreResults);
        setVectors(vectorBatches.flatMap((batch) => batch.vectors));
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : 'No se pudo cargar el escaneo.');
        setScores([]);
        setVectors([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadFindings();

    return () => {
      cancelled = true;
    };
  }, [scanId, severityFilter, page]);

  const rows = useMemo(
    () => (scanDetail ? buildFindingRows(scanDetail.findings.items, scores, vectors) : []),
    [scanDetail, scores, vectors],
  );

  const visibleRows = useMemo(
    () => filterRows(rows, { minScore, falsePositive: fpFilter }),
    [rows, minScore, fpFilter],
  );

  function handleLoadScan() {
    const trimmed = scanIdInput.trim();
    if (!trimmed) return;
    setPage(1);
    setScanId(trimmed);
  }

  function toggleExpanded(id: string) {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function handleMarkFalsePositive(row: FindingRow) {
    if (!scanId) return;

    setMarkingIds((prev) => new Set(prev).add(row.findingId));
    setMarkError(null);

    try {
      await markFalsePositive(scanId, row.finding, {
        findingId: row.findingId,
        user: CURRENT_USER,
      });

      // HU-010 ya excluye por defecto los hallazgos marcados; retiramos la
      // fila localmente en vez de refetchear toda la página + re-evaluar
      // score/vector de los hallazgos restantes.
      setScanDetail((prev) => {
        if (!prev) return prev;
        const items = prev.findings.items.filter((f) => f.template_id !== row.findingId);
        return {
          ...prev,
          findings: {
            ...prev.findings,
            items,
            total: Math.max(0, prev.findings.total - 1),
          },
        };
      });
      setScores((prev) => prev.filter((s) => s.finding_id !== row.findingId));
    } catch (err) {
      setMarkError(
        err instanceof ApiError ? err.message : 'No se pudo marcar el hallazgo como falso positivo.',
      );
    } finally {
      setMarkingIds((prev) => {
        const next = new Set(prev);
        next.delete(row.findingId);
        return next;
      });
    }
  }

  return (
    <div className="dark space-y-6 animate-in fade-in duration-300">
      <div className="bg-card border border-border rounded-xl p-6 shadow-lg space-y-4">
        <div className="flex items-end gap-3 flex-wrap">
          <div className="flex-1 min-w-[280px]">
            <label htmlFor="scan-id-input" className="text-sm text-muted-foreground mb-1 block">
              ID de escaneo (HU-009/HU-010)
            </label>
            <input
              id="scan-id-input"
              type="text"
              value={scanIdInput}
              onChange={(e) => setScanIdInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleLoadScan()}
              placeholder="ej. b3f1c2a4-...-scan-id"
              className="w-full px-3 py-2 rounded-md border border-input bg-input-background text-foreground text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
          <Button onClick={handleLoadScan} disabled={!scanIdInput.trim() || loading}>
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
            Cargar hallazgos
          </Button>
        </div>

        {scanDetail && (
          <div className="flex flex-wrap gap-4 text-sm text-muted-foreground">
            <span>
              Objetivo: <span className="text-foreground font-mono">{scanDetail.target}</span>
            </span>
            <span>
              Estado del escaneo: <span className="text-foreground">{scanDetail.status}</span>
            </span>
            <span>
              Progreso: <span className="text-foreground">{Math.round(scanDetail.progress * 100)}%</span>
            </span>
          </div>
        )}

        <div className="flex flex-wrap gap-3">
          <Select
            value={severityFilter}
            onValueChange={(value) => {
              setSeverityFilter(value as VulnSeverity | 'all');
              setPage(1);
            }}
          >
            <SelectTrigger className="w-[200px]" aria-label="Filtrar por severidad">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SEVERITY_OPTIONS.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select
            value={String(minScore)}
            onValueChange={(value) => setMinScore(Number(value))}
          >
            <SelectTrigger className="w-[200px]" aria-label="Filtrar por confianza">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {CONFIDENCE_OPTIONS.map((opt) => (
                <SelectItem key={opt.value} value={String(opt.value)}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={fpFilter} onValueChange={(value) => setFpFilter(value as FalsePositiveFilter)}>
            <SelectTrigger className="w-[240px]" aria-label="Filtrar por falso positivo">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {FP_OPTIONS.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {error && (
        <div
          role="alert"
          className="flex items-center gap-2 bg-destructive/10 border border-destructive/30 text-destructive rounded-lg p-4 text-sm"
        >
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {markError && (
        <div
          role="alert"
          className="flex items-center gap-2 bg-destructive/10 border border-destructive/30 text-destructive rounded-lg p-4 text-sm"
        >
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {markError}
        </div>
      )}

      {!scanId && !error && (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground border border-dashed border-border rounded-xl">
          <ShieldQuestion className="w-8 h-8 mb-3 opacity-50" />
          <p className="text-sm">Ingresá un ID de escaneo para listar sus hallazgos.</p>
        </div>
      )}

      {scanId && (
        <div className="bg-card border border-border rounded-xl overflow-hidden shadow-lg">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead aria-hidden="true" />
                <TableHead>Severidad</TableHead>
                <TableHead>Hallazgo</TableHead>
                <TableHead>Vector</TableHead>
                <TableHead>Score IA</TableHead>
                <TableHead>Estado</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-10 text-muted-foreground">
                    <Loader2 className="w-4 h-4 animate-spin inline mr-2" />
                    Cargando hallazgos y evaluación de IA...
                  </TableCell>
                </TableRow>
              )}

              {!loading && scanDetail && visibleRows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-10 text-muted-foreground">
                    Sin hallazgos que coincidan con los filtros seleccionados.
                  </TableCell>
                </TableRow>
              )}

              {!loading &&
                visibleRows.map((row) => (
                  <FindingRowGroup
                    key={row.findingId}
                    row={row}
                    expanded={expandedIds.has(row.findingId)}
                    onToggle={() => toggleExpanded(row.findingId)}
                    marking={markingIds.has(row.findingId)}
                    onMarkFalsePositive={() => handleMarkFalsePositive(row)}
                  />
                ))}
            </TableBody>
          </Table>

          {scanDetail && scanDetail.findings.total_pages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-border text-sm text-muted-foreground">
              <span>
                Página {scanDetail.findings.page} de {scanDetail.findings.total_pages} (
                {scanDetail.findings.total} hallazgos)
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  Anterior
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page >= scanDetail.findings.total_pages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Siguiente
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FindingRowGroup({
  row,
  expanded,
  onToggle,
  marking,
  onMarkFalsePositive,
}: {
  row: FindingRow;
  expanded: boolean;
  onToggle: () => void;
  marking: boolean;
  onMarkFalsePositive: () => void;
}) {
  const { finding, score, vector } = row;
  const estado = deriveEstado(score);

  return (
    <>
      <TableRow>
        <TableCell>
          <button
            type="button"
            onClick={onToggle}
            aria-label={expanded ? 'Ocultar evidencia' : 'Mostrar evidencia'}
            aria-expanded={expanded}
            className="text-muted-foreground hover:text-foreground"
          >
            {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>
        </TableCell>
        <TableCell>
          <Badge variant={severityBadgeVariant(finding.severity)}>{finding.severity}</Badge>
        </TableCell>
        <TableCell>
          <div className="font-medium text-foreground">{finding.name}</div>
          <div className="text-xs text-muted-foreground font-mono">{finding.template_id}</div>
        </TableCell>
        <TableCell className="text-sm">{vector ? vector.name : '—'}</TableCell>
        <TableCell>
          {score ? (
            <span className="font-mono">{score.score}/100</span>
          ) : (
            <Loader2 className="w-3.5 h-3.5 animate-spin text-muted-foreground" />
          )}
        </TableCell>
        <TableCell>
          <Badge variant={estado === 'Probable Falso Positivo' ? 'outline' : 'default'}>
            {estado}
          </Badge>
        </TableCell>
      </TableRow>

      {expanded && (
        <TableRow>
          <TableCell colSpan={6} className="bg-muted/30 whitespace-normal">
            <div className="py-3 space-y-3 text-sm">
              <div>
                <span className="text-muted-foreground">URL/host afectado: </span>
                <span className="font-mono">{finding.matched_at}</span>
              </div>
              {finding.description && (
                <div>
                  <span className="text-muted-foreground">Descripción: </span>
                  {finding.description}
                </div>
              )}
              {finding.tags.length > 0 && (
                <div className="flex gap-1.5 flex-wrap">
                  {finding.tags.map((tag) => (
                    <Badge key={tag} variant="secondary">
                      {tag}
                    </Badge>
                  ))}
                </div>
              )}
              {finding.extracted_results.length > 0 && (
                <div>
                  <p className="text-muted-foreground mb-1">Evidencia extraída del escaneo:</p>
                  <pre className="bg-background border border-border rounded-md p-3 text-xs overflow-x-auto whitespace-pre-wrap">
                    {finding.extracted_results.join('\n')}
                  </pre>
                </div>
              )}
              {finding.references.length > 0 && (
                <div>
                  <span className="text-muted-foreground">Referencias: </span>
                  {finding.references.join(', ')}
                </div>
              )}
              {score && (
                <div>
                  <p className="text-muted-foreground mb-1">Explicación del score de confianza (HU-016):</p>
                  <p className="text-xs">{score.explanation}</p>
                </div>
              )}
              {vector && (
                <div>
                  <p className="text-muted-foreground mb-1">
                    Vector de ataque correlacionado (HU-014): {vector.name}
                  </p>
                  <p className="text-xs">{vector.justification}</p>
                  <ol className="text-xs list-decimal list-inside mt-1 space-y-0.5">
                    {vector.chain.map((step, idx) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ol>
                </div>
              )}

              <div className="pt-2 border-t border-border">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={marking}
                  onClick={onMarkFalsePositive}
                  className="text-destructive hover:text-destructive"
                >
                  {marking ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <ShieldOff className="w-3.5 h-3.5" />
                  )}
                  Marcar como falso positivo
                </Button>
              </div>
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}
