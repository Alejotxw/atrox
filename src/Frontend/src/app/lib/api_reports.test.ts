import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { downloadExecutiveReportPdf, setAuthToken } from './api';

describe('downloadExecutiveReportPdf API client (HU-023)', () => {
  beforeEach(() => {
    setAuthToken('mock-session-token');
    vi.restoreAllMocks();
  });

  afterEach(() => {
    setAuthToken(null);
  });

  it('triggers authenticated GET fetch call to /api/reports/executive/{scanId}', async () => {
    const mockBlob = new Blob(['%PDF-1.4 test content'], { type: 'application/pdf' });
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      blob: async () => mockBlob,
    } as Response);

    // Mock DOM download elements
    const createObjectURLSpy = vi.spyOn(window.URL, 'createObjectURL').mockReturnValue('blob:http://localhost/mock-uuid');
    const revokeObjectURLSpy = vi.spyOn(window.URL, 'revokeObjectURL').mockImplementation(() => {});

    await downloadExecutiveReportPdf('test-scan-123');

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, options] = fetchSpy.mock.calls[0];
    expect(String(url)).toContain('/api/reports/executive/test-scan-123');
    expect((options?.headers as Record<string, string>)?.['Authorization']).toBe('Bearer mock-session-token');

    expect(createObjectURLSpy).toHaveBeenCalledWith(mockBlob);
    expect(revokeObjectURLSpy).toHaveBeenCalledWith('blob:http://localhost/mock-uuid');
  });
});
