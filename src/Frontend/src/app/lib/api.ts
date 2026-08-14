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
  // Presentes solo cuando mfa_required === true (sysadmin único, con TOTP)
  mfa_token?: string;
  message?: string;
  // Presentes solo cuando mfa_required === false (cuentas regulares, sin TOTP)
  session_token?: string;
  expires_in_minutes?: number;
  user?: { username: string; role: string };
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
  role: 'SysAdmin' | 'Usuario';
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

// -- Tipos que reflejan atrox/access_requests/models.py (landing page pre-login) --

export interface AccessRequestPayload {
  full_name: string;
  email: string;
  organization: string;
  role: string;
  reason: string;
}

export interface AccessRequestResponse extends AccessRequestPayload {
  id: string;
  created_at: string;
}

export function submitAccessRequestApi(payload: AccessRequestPayload): Promise<AccessRequestResponse> {
  return request<AccessRequestResponse>('/api/access-requests', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

// -- Panel de administración: solicitudes de acceso y cuentas (super admin) ----

export type AccessRequestStatus = 'pending' | 'approved' | 'rejected';

export interface AdminAccessRequest extends AccessRequestPayload {
  id: string;
  status: AccessRequestStatus;
  reviewed_at: string | null;
  review_reason: string | null;
  account_id: string | null;
  created_at: string;
}

export interface AccessRequestListResult {
  total: number;
  requests: AdminAccessRequest[];
}

export function listAccessRequestsApi(): Promise<AccessRequestListResult> {
  return request<AccessRequestListResult>('/api/access-requests');
}

export type AccountStatus = 'active' | 'suspended' | 'deleted';
export type ModerationNoteKind = 'warning' | 'report';

export interface ModerationNote {
  id: string;
  kind: ModerationNoteKind;
  reason: string;
  created_by: string;
  created_at: string;
}

export interface Account {
  id: string;
  username: string;
  full_name: string;
  email: string;
  organization: string;
  role: string;
  status: AccountStatus;
  access_request_id: string | null;
  moderation_notes: ModerationNote[];
  created_at: string;
}

export interface AccountListResult {
  total: number;
  accounts: Account[];
}

export interface ApproveAccessRequestResponse {
  account: Account;
  temporary_password: string;
}

export function approveAccessRequestApi(requestId: string): Promise<ApproveAccessRequestResponse> {
  return request<ApproveAccessRequestResponse>(`/api/access-requests/${requestId}/approve`, {
    method: 'POST',
  });
}

export function rejectAccessRequestApi(requestId: string, reason?: string): Promise<AdminAccessRequest> {
  return request<AdminAccessRequest>(`/api/access-requests/${requestId}/reject`, {
    method: 'POST',
    body: reason ? JSON.stringify({ reason }) : undefined,
  });
}

export function listAccountsApi(): Promise<AccountListResult> {
  return request<AccountListResult>('/api/accounts');
}

export function suspendAccountApi(accountId: string): Promise<Account> {
  return request<Account>(`/api/accounts/${accountId}/suspend`, { method: 'POST' });
}

export function reactivateAccountApi(accountId: string): Promise<Account> {
  return request<Account>(`/api/accounts/${accountId}/reactivate`, { method: 'POST' });
}

export function deleteAccountApi(accountId: string): Promise<Account> {
  return request<Account>(`/api/accounts/${accountId}`, { method: 'DELETE' });
}

export function warnAccountApi(accountId: string, reason: string): Promise<Account> {
  return request<Account>(`/api/accounts/${accountId}/warnings`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
}

export function reportAccountApi(accountId: string, reason: string): Promise<Account> {
  return request<Account>(`/api/accounts/${accountId}/reports`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
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
  source: 'llm' | 'heuristic';
  model_used: string | null;
}

export function analyzeVectors(findings: VulnFinding[]): Promise<VectorAnalysisResult> {
  return request<VectorAnalysisResult>('/api/ai/vectors/analyze', {
    method: 'POST',
    body: JSON.stringify({ findings }),
  });
}

// -- Chat de IA sobre hallazgos (Motor Ollama IA) ------------------------------

export interface ChatResponse {
  response: string;
  model_used: string;
}

export function sendChatMessage(message: string, context?: string): Promise<ChatResponse> {
  return request<ChatResponse>('/api/ai/chat', {
    method: 'POST',
    body: JSON.stringify({ message, context: context ?? null }),
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

// -- Tipos y función para Reporte Ejecutivo PDF (HU-023) -------------------------

export async function downloadExecutiveReportPdf(scanId: string): Promise<void> {
  const headers: Record<string, string> = {};
  if (activeSessionToken) {
    headers['Authorization'] = `Bearer ${activeSessionToken}`;
  }

  const response = await fetch(`${API_BASE_URL}/api/reports/executive/${scanId}`, {
    method: 'GET',
    headers,
  });

  if (!response.ok) {
    let detail: unknown = response.statusText;
    try {
      const body = await response.json();
      detail = body?.detail ?? body;
    } catch {
      // Ignorar no-json
    }
    throw new ApiError(response.status, detail);
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `reporte_ejecutivo_${scanId}.pdf`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}

// -- Función para Reporte Técnico (PDF/HTML) (HU-024) -----------------------------

export async function downloadTechnicalReport(
  scanId: string,
  format: 'pdf' | 'html' = 'pdf',
): Promise<void> {
  const headers: Record<string, string> = {};
  if (activeSessionToken) {
    headers['Authorization'] = `Bearer ${activeSessionToken}`;
  }

  const response = await fetch(`${API_BASE_URL}/api/reports/technical/${scanId}?format=${format}`, {
    method: 'GET',
    headers,
  });

  if (!response.ok) {
    let detail: unknown = response.statusText;
    try {
      const body = await response.json();
      detail = body?.detail ?? body;
    } catch {
      // Ignorar no-json
    }
    throw new ApiError(response.status, detail);
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `reporte_tecnico_${scanId}.${format}`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}

// -- Tipos que reflejan atrox/queue/models.py (HU-004 / listado para HU-019) ---

export type JobType = 'discovery' | 'vulnscan';
export type JobStatus = 'pending' | 'running' | 'done' | 'failed';

export interface Job {
  id: string;
  job_type: JobType;
  status: JobStatus;
  params: Record<string, unknown>;
  result: Record<string, unknown> | null;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

/** Lista todos los trabajos — base para agregar KPIs del dashboard (HU-019). */
export function listJobs(): Promise<Job[]> {
  return request<Job[]>('/api/jobs');
}

// -- Consola en vivo SSE (HU-020) ---------------------------------------------
// El stream se consume directamente vía GET /api/console/stream
// (ver src/app/lib/scanConsoleStream.ts); no hay endpoint de demo — los
// eventos los emite el backend real al procesar jobs vía POST /api/jobs.
