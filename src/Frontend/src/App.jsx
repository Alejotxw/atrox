import { useState, useEffect, useCallback } from 'react';
import './App.css';

const API_BASE = 'http://localhost:3000/api';

function App() {
  const [status, setStatus] = useState({
    lastSync: null,
    status: 'PENDING',
    records: 0,
    isSyncing: false,
    totalCves: 0,
    error: null
  });
  const [cves, setCves] = useState([]);
  const [loadingCves, setLoadingCves] = useState(false);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCvesCount, setTotalCvesCount] = useState(0);

  // Fetch sync status
  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/sync/status`);
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      }
    } catch (err) {
      console.error('Error fetching sync status:', err);
    }
  }, []);

  // Fetch CVEs with pagination & filters
  const fetchCves = useCallback(async () => {
    setLoadingCves(true);
    try {
      const queryParams = new URLSearchParams({
        page: page.toString(),
        limit: '10',
        search,
        severity
      });
      const res = await fetch(`${API_BASE}/sync/cves?${queryParams}`);
      if (res.ok) {
        const data = await res.json();
        setCves(data.cves || []);
        setTotalPages(data.pagination?.totalPages || 1);
        setTotalCvesCount(data.pagination?.total || 0);
      }
    } catch (err) {
      console.error('Error fetching CVE catalog:', err);
    } finally {
      setLoadingCves(false);
    }
  }, [page, search, severity]);

  // Initial load
  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  useEffect(() => {
    fetchCves();
  }, [fetchCves]);

  // Poll status while syncing is in progress
  useEffect(() => {
    let intervalId;
    if (status.isSyncing) {
      intervalId = setInterval(() => {
        fetchStatus();
        fetchCves(); // also reload list to show incoming items
      }, 2000);
    } else {
      // Periodic check every 15 seconds
      intervalId = setInterval(fetchStatus, 15000);
    }
    return () => clearInterval(intervalId);
  }, [status.isSyncing, fetchStatus, fetchCves]);

  // Trigger manual sync
  const handleTriggerSync = async () => {
    if (status.isSyncing) return;
    try {
      setStatus(prev => ({ ...prev, isSyncing: true }));
      const res = await fetch(`${API_BASE}/sync/trigger`, { method: 'POST' });
      if (res.ok) {
        fetchStatus();
      } else {
        const errData = await res.json();
        alert(`Error al iniciar la sincronización: ${errData.error || 'Error desconocido'}`);
        fetchStatus();
      }
    } catch (err) {
      alert('Error de conexión al servidor.');
      fetchStatus();
    }
  };

  // Reset filters
  const handleResetFilters = () => {
    setSearch('');
    setSeverity('');
    setPage(1);
  };

  const getSeverityBadgeClass = (score) => {
    if (!score) return 'badge-na';
    if (score >= 9.0) return 'badge-critical';
    if (score >= 7.0) return 'badge-high';
    if (score >= 4.0) return 'badge-medium';
    return 'badge-low';
  };

  const getSeverityLabel = (score) => {
    if (!score) return 'N/A';
    if (score >= 9.0) return `Crítica (${score})`;
    if (score >= 7.0) return `Alta (${score})`;
    if (score >= 4.0) return `Media (${score})`;
    return `Baja (${score})`;
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return 'Nunca';
    return new Date(dateStr).toLocaleString('es-ES', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  return (
    <div className="admin-container">
      {/* Header */}
      <header className="admin-header">
        <div className="header-logo">
          <div className="logo-icon"></div>
          <h1>ATROX</h1>
          <span className="badge-system">SISTEMA</span>
        </div>
        <p className="header-subtitle">Gestión y Sincronización de Base de Amenazas (NVD CVE)</p>
      </header>

      {/* Sync Status Section */}
      <section className="dashboard-grid">
        <div className="glass-card status-card">
          <h2>Estado del Sincronizador Diario</h2>
          <div className="status-indicator-bar">
            <span className={`status-dot ${status.isSyncing ? 'status-syncing' : status.status === 'SUCCESS' ? 'status-success' : 'status-error'}`}></span>
            <span className="status-text">
              {status.isSyncing ? 'Sincronizando...' : status.status === 'SUCCESS' ? 'Sincronizado' : 'Error en última ejecución'}
            </span>
          </div>

          <div className="details-grid">
            <div className="detail-item">
              <span className="detail-label">Última Sincronización</span>
              <span className="detail-val">{formatDate(status.lastSync)}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Nuevos/Modificados</span>
              <span className="detail-val">{status.records} registros</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Catálogo en BD</span>
              <span className="detail-val total-cve-badge">{status.totalCves} CVEs</span>
            </div>
          </div>

          {status.error && (
            <div className="error-alert">
              <strong>Error de Red/API:</strong>
              <p>{status.error}</p>
            </div>
          )}

          <div className="action-row">
            <button
              onClick={handleTriggerSync}
              disabled={status.isSyncing}
              className={`btn ${status.isSyncing ? 'btn-disabled' : 'btn-primary'}`}
            >
              {status.isSyncing ? (
                <>
                  <span className="spinner"></span> Sincronizando catálogo...
                </>
              ) : (
                'Sincronizar Ahora'
              )}
            </button>
            <button onClick={fetchStatus} disabled={status.isSyncing} className="btn btn-secondary">
              Actualizar Estado
            </button>
          </div>
        </div>
      </section>

      {/* CVE Catalog Table */}
      <section className="catalog-section">
        <div className="glass-card catalog-card">
          <div className="card-header">
            <h2>Catálogo de Amenazas Vulnerables</h2>
            <span className="count-label">({totalCvesCount} encontrados)</span>
          </div>

          {/* Filter Bar */}
          <div className="filters-bar">
            <div className="input-group">
              <input
                type="text"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
                placeholder="Buscar por ID (CVE-2026-...) o palabra clave..."
                className="search-input"
              />
            </div>
            <div className="input-group-select">
              <select
                value={severity}
                onChange={(e) => {
                  setSeverity(e.target.value);
                  setPage(1);
                }}
                className="severity-select"
              >
                <option value="">Todas las Severidades</option>
                <option value="Critical">Crítica (CVSS 9.0 - 10.0)</option>
                <option value="High">Alta (CVSS 7.0 - 8.9)</option>
                <option value="Medium">Media (CVSS 4.0 - 6.9)</option>
                <option value="Low">Baja (CVSS 0.1 - 3.9)</option>
              </select>
            </div>
            <button onClick={handleResetFilters} className="btn btn-clear">
              Limpiar
            </button>
          </div>

          {/* Table Container */}
          <div className="table-responsive">
            {loadingCves ? (
              <div className="table-loader">
                <span className="spinner-large"></span>
                <p>Cargando catálogo de vulnerabilidades...</p>
              </div>
            ) : cves.length === 0 ? (
              <div className="table-empty">
                <p>No se encontraron registros de CVE.</p>
                {status.totalCves === 0 && (
                  <p className="help-text">La base de amenazas está vacía. Presione "Sincronizar Ahora" arriba para descargar CVEs.</p>
                )}
              </div>
            ) : (
              <table className="cve-table">
                <thead>
                  <tr>
                    <th>Código CVE-ID</th>
                    <th>Severidad CVSS</th>
                    <th>Descripción en Inglés</th>
                    <th>Última Modificación</th>
                  </tr>
                </thead>
                <tbody>
                  {cves.map((cve) => (
                    <tr key={cve.cveId}>
                      <td className="cve-id-cell">{cve.cveId}</td>
                      <td>
                        <span className={`badge ${getSeverityBadgeClass(cve.cvss)}`}>
                          {getSeverityLabel(cve.cvss)}
                        </span>
                      </td>
                      <td className="description-cell" title={cve.description}>
                        {cve.description || <span className="no-desc">Sin descripción disponible</span>}
                      </td>
                      <td className="date-cell">{formatDate(cve.modified)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Pagination Controls */}
          {totalPages > 1 && (
            <div className="pagination-row">
              <button
                disabled={page <= 1}
                onClick={() => setPage(prev => prev - 1)}
                className="btn btn-nav"
              >
                &laquo; Anterior
              </button>
              <span className="pagination-info">
                Página <strong>{page}</strong> de {totalPages}
              </span>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage(prev => prev + 1)}
                className="btn btn-nav"
              >
                Siguiente &raquo;
              </button>
            </div>
          )}
        </div>
      </section>

      <footer className="admin-footer">
        <p>Framework ATROX - Sincronizador de Vulnerabilidades NVD diariamente</p>
      </footer>
    </div>
  );
}

export default App;
