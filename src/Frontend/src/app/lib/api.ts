/**
 * Cliente HTTP tipado hacia el backend Atrox (HU-010, HU-014, HU-016).
 * No hay librería HTTP instalada en el proyecto (ni axios ni ky) — fetch nativo alcanza.
 */

const API_BASE_URL: string =
  (import.meta as any).env?.VITE_API_BASE_URL ?? 'http://localhost:8000';

export class ApiError extends Error {
  status: number;
  detail: unknown;

  constructor(status: number, detail: unknown) {
    super(
      `Error ${status} del backend: ${
        typeof detail === 'string' ? detail : JSON.stringify(detail)
      }`,
    );
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });

  if (!response.ok) {
    let detail: unknown = response.statusText;
    try {
      const body = await response.json();
      detail = body?.detail ?? body;
    } catch {
      // El cuerpo no era JSON — nos quedamos con statusText.
    }
    throw new ApiError(response.status, detail);
  }

  return response.json() as Promise<T>;
}

// -- Tipos que reflejan atrox/scanner/models.py --------------------------------

export type VulnSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical' | 'unknown';

export interface VulnFinding {
  template_id: string;
  name: string;
  severity: VulnSeverity;
  host: string;
  matched_at: string;
  tags: string[];
  description: string;
  references: string[];
  extracted_results: string[];
  scan_type: string;
  ip: string;
  timestamp: string;
}

// -- Tipos que reflejan atrox/api/scans.py (HU-010) -----------------------------

export interface PaginatedFindings {
  items: VulnFinding[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface HostFinding {
  address: string;
  status: string;
  ports: { port: number; protocol: string; service: string; version: string }[];
}

export interface ScanDetailResponse {
  scan_id: string;
  scan_type: 'discovery' | 'vulnscan';
  status: 'pending' | 'running' | 'done' | 'failed';
  progress: number;
  target: string;
  assets: HostFinding[];
  findings: PaginatedFindings;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface GetScanDetailParams {
  severity?: VulnSeverity;
  assetStatus?: string;
  page?: number;
  pageSize?: number;
}

export function getScanDetail(
  scanId: string,
  params: GetScanDetailParams = {},
): Promise<ScanDetailResponse> {
  const query = new URLSearchParams();
  if (params.severity) query.set('severity', params.severity);
  if (params.assetStatus) query.set('asset_status', params.assetStatus);
  query.set('page', String(params.page ?? 1));
  query.set('page_size', String(params.pageSize ?? 10));

  return request<ScanDetailResponse>(`/api/scans/${scanId}?${query.toString()}`);
}

// -- Tipos que reflejan atrox/ai/agents/scoring/models.py (HU-016) --------------

export interface ConfidenceScoreResult {
  finding_id: string;
  score: number;
  threshold: number;
  probable_fp: boolean;
  explanation: string;
  generation_time_ms: number;
  within_sla: boolean;
}

export function scoreFinding(
  finding: VulnFinding,
  options: { findingId?: string; threshold?: number } = {},
): Promise<ConfidenceScoreResult> {
  return request<ConfidenceScoreResult>('/api/ai/scoring/score', {
    method: 'POST',
    body: JSON.stringify({
      finding,
      finding_id: options.findingId,
      threshold: options.threshold,
    }),
  });
}

// -- Tipos que reflejan atrox/ai/agents/vectors/models.py (HU-014) --------------

export interface AttackVector {
  rank: number;
  vector_id: string;
  name: string;
  severity_score: number;
  finding_ids: string[];
  chain: string[];
  justification: string;
  estimated_impact: string;
}

export interface VectorAnalysisResult {
  vectors: AttackVector[];
  total_findings: number;
  analysis_time_ms: number;
  within_sla: boolean;
}

export function analyzeVectors(findings: VulnFinding[]): Promise<VectorAnalysisResult> {
  return request<VectorAnalysisResult>('/api/ai/vectors/analyze', {
    method: 'POST',
    body: JSON.stringify({ findings }),
  });
}
