import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { downloadExecutiveReportPdf, downloadTechnicalReport, setAuthToken } from './api';

describe('Report Export API client (HU-023 & HU-024)', () => {
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

  it('triggers authenticated GET fetch call to /api/reports/technical/{scanId}?format=html', async () => {
    const mockBlob = new Blob(['<!DOCTYPE html><html></html>'], { type: 'text/html' });
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      blob: async () => mockBlob,
    } as Response);

    const createObjectURLSpy = vi.spyOn(window.URL, 'createObjectURL').mockReturnValue('blob:http://localhost/mock-uuid-html');
    const revokeObjectURLSpy = vi.spyOn(window.URL, 'revokeObjectURL').mockImplementation(() => {});

    await downloadTechnicalReport('test-scan-456', 'html');

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, options] = fetchSpy.mock.calls[0];
    expect(String(url)).toContain('/api/reports/technical/test-scan-456?format=html');
    expect((options?.headers as Record<string, string>)?.['Authorization']).toBe('Bearer mock-session-token');

    expect(createObjectURLSpy).toHaveBeenCalledWith(mockBlob);
    expect(revokeObjectURLSpy).toHaveBeenCalledWith('blob:http://localhost/mock-uuid-html');
  });
});
