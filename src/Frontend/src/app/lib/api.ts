/**
 * Cliente HTTP tipado hacia el backend Atrox (HU-010, HU-014, HU-016, HU-022).
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

export function describeError(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}

let activeSessionToken: string | null = sessionStorage.getItem('atrox_session_token');

export function setAuthToken(token: string | null): void {
  activeSessionToken = token;
  if (token) {
    sessionStorage.setItem('atrox_session_token', token);
  } else {
    sessionStorage.removeItem('atrox_session_token');
  }
}

export function getAuthToken(): string | null {
  return activeSessionToken;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init?.headers as Record<string, string> ?? {}),
  };

  if (activeSessionToken && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${activeSessionToken}`;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers,
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

// -- Tipos que reflejan atrox/api/auth.py (HU-018) ------------------------------

export interface LoginStep1Response {
  mfa_required: boolean;
  mfa_token: string;
  message: string;
}

export interface MfaVerifyResponse {
  session_token: string;
  expires_in_minutes: number;
  user: {
    username: string;
    role: string;
  };
}

export interface MfaSetupResponse {
  username: string;
  secret: string;
  otpauth_url: string;
}

export interface UserStatusResponse {
  username: string;
  expires_at: number;
  seconds_remaining: number;
}

export function loginApi(username: string, password: string): Promise<LoginStep1Response> {
  return request<LoginStep1Response>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
}

export function verifyMfaApi(mfaToken: string, code: string): Promise<MfaVerifyResponse> {
  return request<MfaVerifyResponse>('/api/auth/mfa/verify', {
    method: 'POST',
    body: JSON.stringify({ mfa_token: mfaToken, code }),
  });
}

export function getMfaSetupApi(): Promise<MfaSetupResponse> {
  return request<MfaSetupResponse>('/api/auth/mfa/setup');
}

export function getMeApi(): Promise<UserStatusResponse> {
  return request<UserStatusResponse>('/api/auth/me');
}

export function logoutApi(): Promise<{ message: string }> {
  return request<{ message: string }>('/api/auth/logout', {
    method: 'POST',
  });
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

// -- Tipos que reflejan atrox/api/scans.py (HU-009/HU-010) ----------------------

export type ScanType = 'discovery' | 'vulnscan';

export interface ScanCreateResponse {
  scan_id: string;
  status: string;
}

export function createScan(
  target: string,
  scanType: ScanType,
  params: object = {},
): Promise<ScanCreateResponse> {
  return request<ScanCreateResponse>('/api/scans', {
    method: 'POST',
    body: JSON.stringify({ target, scan_type: scanType, params }),
  });
}


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

// -- Tipos que reflejan atrox/findings/models.py (HU-022) -----------------------

export interface FalsePositiveMarkResponse {
  id: string;
  scan_id: string;
  finding_id: string;
  user: string;
  reason: string | null;
  marked_at: string;
}

// -- Tipos que reflejan atrox/api/health.py --------------------------------------

export interface HealthResponse {
  status: string;
  service: string;
  environment: string;
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health');
}

export function markFalsePositive(
  scanId: string,
  finding: VulnFinding,
  options: { findingId?: string; reason?: string; user?: string } = {},
): Promise<FalsePositiveMarkResponse> {
  return request<FalsePositiveMarkResponse>(`/api/scans/${scanId}/findings/false-positive`, {
    method: 'POST',
    headers: options.user ? { 'X-Atrox-User': options.user } : undefined,
    body: JSON.stringify({
      finding,
      finding_id: options.findingId,
      reason: options.reason,
    }),
  });
}
