import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import FindingsManagementView from './FindingsManagementView';

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api');
  return {
    ...actual,
    getScanDetail: vi.fn(),
    scoreFinding: vi.fn(),
    analyzeVectors: vi.fn(),
    markFalsePositive: vi.fn(),
  };
});

import {
  analyzeVectors,
  getScanDetail,
  markFalsePositive,
  scoreFinding,
  ApiError,
} from '../../lib/api';

const SCAN_ID = '11111111-1111-1111-1111-111111111111';

const STRONG_FINDING = {
  template_id: 'cve-2021-41773',
  name: 'Apache Path Traversal',
  severity: 'critical' as const,
  host: 'http://example.com',
  matched_at: 'http://example.com/cgi-bin/.%2e/etc/passwd',
  tags: ['cve', 'rce'],
  description: 'Path traversal confirmado.',
  references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-41773'],
  extracted_results: ['root:x:0:0:root:/root:/bin/bash'],
  scan_type: 'http',
  ip: '10.0.0.1',
  timestamp: '2026-07-31T00:00:00Z',
};

const WEAK_FINDING = {
  template_id: 'tech-detect-nginx',
  name: 'Nginx Detection',
  severity: 'info' as const,
  host: 'http://example.com',
  matched_at: 'http://example.com/',
  tags: ['tech', 'fingerprint'],
  description: '',
  references: [],
  extracted_results: [],
  scan_type: 'http',
  ip: '10.0.0.1',
  timestamp: '2026-07-31T00:00:00Z',
};

function mockScanDetail(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    scan_id: SCAN_ID,
    scan_type: 'vulnscan',
    status: 'done',
    progress: 1,
    target: 'example.com',
    assets: [],
    findings: {
      items: [STRONG_FINDING, WEAK_FINDING],
      total: 2,
      page: 1,
      page_size: 10,
      total_pages: 1,
    },
    error: null,
    created_at: '2026-07-31T00:00:00Z',
    started_at: '2026-07-31T00:00:00Z',
    finished_at: '2026-07-31T00:00:01Z',
    ...overrides,
  };
}

function setupHappyPath() {
  vi.mocked(getScanDetail).mockResolvedValue(mockScanDetail() as any);
  vi.mocked(scoreFinding).mockImplementation((finding: any) => {
    if (finding.template_id === STRONG_FINDING.template_id) {
      return Promise.resolve({
        finding_id: STRONG_FINDING.template_id,
        score: 90,
        threshold: 40,
        probable_fp: false,
        explanation: 'severidad critical (base 70); evidencia (+15); cve (+10); 1 referencia (+5) -> score 90/100 (umbral 40)',
        generation_time_ms: 0.2,
        within_sla: true,
      });
    }
    return Promise.resolve({
      finding_id: WEAK_FINDING.template_id,
      score: 0,
      threshold: 40,
      probable_fp: true,
      explanation: 'severidad info (base 20); tags de fingerprinting (-20); sin descripción (-10) -> score 0/100 (umbral 40)',
      generation_time_ms: 0.1,
      within_sla: true,
    });
  });
  vi.mocked(analyzeVectors).mockResolvedValue({
    vectors: [
      {
        rank: 1,
        vector_id: `standalone:${STRONG_FINDING.template_id}`,
        name: 'Explotación directa: Apache Path Traversal',
        severity_score: 8.5,
        finding_ids: [STRONG_FINDING.template_id],
        chain: ['Leer /etc/passwd vía path traversal'],
        justification: 'Hallazgo critical detectado por plantilla cve-2021-41773.',
        estimated_impact: 'Compromiso del servidor',
      },
      {
        rank: 2,
        vector_id: `standalone:${WEAK_FINDING.template_id}`,
        name: 'Explotación directa: Nginx Detection',
        severity_score: 1,
        finding_ids: [WEAK_FINDING.template_id],
        chain: ['Fingerprint de tecnología'],
        justification: 'Hallazgo info, solo fingerprinting.',
        estimated_impact: 'Bajo',
      },
    ],
    total_findings: 2,
    analysis_time_ms: 0.3,
    within_sla: true,
  } as any);
}

async function loadScan(user: ReturnType<typeof userEvent.setup>) {
  const input = screen.getByLabelText(/ID de escaneo/i);
  await user.type(input, SCAN_ID);
  await user.click(screen.getByRole('button', { name: /cargar hallazgos/i }));
}

beforeEach(() => {
  vi.mocked(getScanDetail).mockReset();
  vi.mocked(scoreFinding).mockReset();
  vi.mocked(analyzeVectors).mockReset();
  vi.mocked(markFalsePositive).mockReset();
});

describe('FindingsManagementView', () => {
  it('shows an empty prompt and makes no API calls before a scan id is entered', () => {
    render(<FindingsManagementView />);

    expect(screen.getByText(/Ingresá un ID de escaneo/i)).toBeInTheDocument();
    expect(getScanDetail).not.toHaveBeenCalled();
  });

  it('calls GET /api/scans/{id} (HU-010) with the entered scan id on load', async () => {
    setupHappyPath();
    const user = userEvent.setup();
    render(<FindingsManagementView />);

    await loadScan(user);

    await waitFor(() => expect(getScanDetail).toHaveBeenCalledTimes(1));
    expect(getScanDetail).toHaveBeenCalledWith(
      SCAN_ID,
      expect.objectContaining({ severity: undefined, page: 1, pageSize: 10 }),
    );
  });

  it('renders a table row per finding with severity, vector, AI score and estado columns', async () => {
    setupHappyPath();
    const user = userEvent.setup();
    render(<FindingsManagementView />);

    await loadScan(user);

    const strongRow = (await screen.findByText('Apache Path Traversal')).closest('tr') as HTMLElement;
    expect(within(strongRow).getByText('critical')).toBeInTheDocument();
    expect(within(strongRow).getByText('Explotación directa: Apache Path Traversal')).toBeInTheDocument();
    expect(within(strongRow).getByText('90/100')).toBeInTheDocument();
    expect(within(strongRow).getByText('Válido')).toBeInTheDocument();

    const weakRow = screen.getByText('Nginx Detection').closest('tr') as HTMLElement;
    expect(within(weakRow).getByText('0/100')).toBeInTheDocument();
    expect(within(weakRow).getByText('Probable Falso Positivo')).toBeInTheDocument();
  });

  it('expands a row to reveal scan evidence not shown in the collapsed row', async () => {
    setupHappyPath();
    const user = userEvent.setup();
    render(<FindingsManagementView />);

    await loadScan(user);
    await screen.findByText('Apache Path Traversal');

    expect(screen.queryByText(/root:x:0:0:root/)).not.toBeInTheDocument();

    const toggles = screen.getAllByRole('button', { name: /mostrar evidencia/i });
    await user.click(toggles[0]);

    expect(await screen.findByText(/root:x:0:0:root/)).toBeInTheDocument();
    expect(screen.getByText(/Path traversal confirmado\./)).toBeInTheDocument();
  });

  it('shows an alert when the HU-010 API call fails', async () => {
    vi.mocked(getScanDetail).mockRejectedValue(new ApiError(404, 'Escaneo no encontrado'));
    const user = userEvent.setup();
    render(<FindingsManagementView />);

    await loadScan(user);

    expect(await screen.findByRole('alert')).toHaveTextContent(/Escaneo no encontrado/);
  });

  it('re-fetches HU-010 with the selected severity filter', async () => {
    setupHappyPath();
    const user = userEvent.setup();
    render(<FindingsManagementView />);

    await loadScan(user);
    await screen.findByText('Apache Path Traversal');

    await user.click(screen.getByLabelText(/Filtrar por severidad/i));
    await user.click(await screen.findByRole('option', { name: 'Crítica' }));

    await waitFor(() =>
      expect(getScanDetail).toHaveBeenLastCalledWith(
        SCAN_ID,
        expect.objectContaining({ severity: 'critical' }),
      ),
    );
  });

  it('filters out probable false positives client-side without refetching', async () => {
    setupHappyPath();
    const user = userEvent.setup();
    render(<FindingsManagementView />);

    await loadScan(user);
    await screen.findByText('Apache Path Traversal');
    await screen.findByText('Nginx Detection');

    await user.click(screen.getByLabelText(/Filtrar por falso positivo/i));
    await user.click(await screen.findByRole('option', { name: 'Solo válidos' }));

    await waitFor(() => expect(screen.queryByText('Nginx Detection')).not.toBeInTheDocument());
    expect(screen.getByText('Apache Path Traversal')).toBeInTheDocument();
    expect(getScanDetail).toHaveBeenCalledTimes(1);
  });

  describe('marcado manual de falso positivo (HU-022)', () => {
    it('calls markFalsePositive with the scan id, finding and current user on click', async () => {
      setupHappyPath();
      vi.mocked(markFalsePositive).mockResolvedValue({
        id: 'mark-1',
        scan_id: SCAN_ID,
        finding_id: WEAK_FINDING.template_id,
        user: 'Admin SecOps',
        reason: null,
        marked_at: '2026-07-31T00:00:00Z',
      });
      const user = userEvent.setup();
      render(<FindingsManagementView />);

      await loadScan(user);
      await screen.findByText('Nginx Detection');

      const toggles = screen.getAllByRole('button', { name: /mostrar evidencia/i });
      await user.click(toggles[1]); // fila de Nginx Detection (weak finding)

      await user.click(await screen.findByRole('button', { name: /marcar como falso positivo/i }));

      await waitFor(() =>
        expect(markFalsePositive).toHaveBeenCalledWith(
          SCAN_ID,
          expect.objectContaining({ template_id: WEAK_FINDING.template_id }),
          expect.objectContaining({ findingId: WEAK_FINDING.template_id, user: 'Admin SecOps' }),
        ),
      );
    });

    it('removes the finding from the table after a successful mark', async () => {
      setupHappyPath();
      vi.mocked(markFalsePositive).mockResolvedValue({
        id: 'mark-1',
        scan_id: SCAN_ID,
        finding_id: WEAK_FINDING.template_id,
        user: 'Admin SecOps',
        reason: null,
        marked_at: '2026-07-31T00:00:00Z',
      });
      const user = userEvent.setup();
      render(<FindingsManagementView />);

      await loadScan(user);
      await screen.findByText('Nginx Detection');

      const toggles = screen.getAllByRole('button', { name: /mostrar evidencia/i });
      await user.click(toggles[1]);
      await user.click(await screen.findByRole('button', { name: /marcar como falso positivo/i }));

      await waitFor(() => expect(screen.queryByText('Nginx Detection')).not.toBeInTheDocument());
      expect(screen.getByText('Apache Path Traversal')).toBeInTheDocument();
    });

    it('shows an alert and keeps the row when marking fails', async () => {
      setupHappyPath();
      vi.mocked(markFalsePositive).mockRejectedValue(new ApiError(500, 'Error al persistir el marcado'));
      const user = userEvent.setup();
      render(<FindingsManagementView />);

      await loadScan(user);
      await screen.findByText('Nginx Detection');

      const toggles = screen.getAllByRole('button', { name: /mostrar evidencia/i });
      await user.click(toggles[1]);
      await user.click(await screen.findByRole('button', { name: /marcar como falso positivo/i }));

      expect(await screen.findByRole('alert')).toHaveTextContent(/Error al persistir el marcado/);
      expect(screen.getByText('Nginx Detection')).toBeInTheDocument();
    });
  });
});
