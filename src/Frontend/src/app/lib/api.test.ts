import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiError, createScan } from './api';

function mockFetchOnce(response: { ok: boolean; status?: number; json: () => Promise<unknown> }) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: response.ok,
    status: response.status ?? (response.ok ? 202 : 422),
    statusText: response.ok ? 'OK' : 'Unprocessable Entity',
    json: response.json,
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('createScan', () => {
  it('POSTs to /api/scans with target, scan_type and params, and returns scan_id/status', async () => {
    const fetchMock = mockFetchOnce({
      ok: true,
      status: 202,
      json: async () => ({ scan_id: '11111111-1111-1111-1111-111111111111', status: 'pending' }),
    });

    const result = await createScan('example.com', 'discovery');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('http://localhost:8000/api/scans');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body)).toEqual({ target: 'example.com', scan_type: 'discovery', params: {} });

    expect(result).toEqual({ scan_id: '11111111-1111-1111-1111-111111111111', status: 'pending' });
  });

  it('throws ApiError with the backend detail when the target is rejected (422)', async () => {
    mockFetchOnce({
      ok: false,
      status: 422,
      json: async () => ({ detail: 'target inválido' }),
    });

    await expect(createScan('', 'discovery')).rejects.toThrow(ApiError);
    await expect(createScan('', 'discovery')).rejects.toMatchObject({ status: 422, detail: 'target inválido' });
  });
});
