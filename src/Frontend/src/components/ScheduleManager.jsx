import { useState, useEffect } from 'react';

const API_BASE = 'http://localhost:3000/api';

const PRESETS_INFO = [
  { id: 'daily', label: 'Diario (Cada noche a medianoche)', cron: '0 0 * * *' },
  { id: 'weekly', label: 'Semanal (Cada domingo a medianoche)', cron: '0 0 * * 0' },
  { id: 'monthly', label: 'Mensual (Día 1 de cada mes)', cron: '0 0 1 * *' },
  { id: 'custom', label: 'Personalizado (Expresión Cron manual)', cron: '' }
];

export default function ScheduleManager() {
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actionMessage, setActionMessage] = useState(null);

  // Form State
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    target: '',
    preset: 'daily',
    cronExpression: '0 0 * * *',
    isActive: true
  });

  const fetchSchedules = async () => {
    try {
      const res = await fetch(`${API_BASE}/schedules`);
      if (!res.ok) throw new Error('Error al cargar la lista de programaciones');
      const data = await res.json();
      setSchedules(data);
      setError(null);
    } catch (err) {
      console.error(err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let active = true;
    fetch(`${API_BASE}/schedules`)
      .then(res => {
        if (!res.ok) throw new Error('Error al cargar la lista de programaciones');
        return res.json();
      })
      .then(data => {
        if (active) {
          setSchedules(data);
          setError(null);
        }
      })
      .catch(err => {
        if (active) {
          console.error(err);
          setError(err.message);
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, []);

  const showNotification = (msg, isSuccess = true) => {
    setActionMessage({ text: msg, isSuccess });
    setTimeout(() => setActionMessage(null), 4000);
  };

  const handlePresetChange = (e) => {
    const presetId = e.target.value;
    const selected = PRESETS_INFO.find(p => p.id === presetId);
    setFormData(prev => ({
      ...prev,
      preset: presetId,
      cronExpression: selected && selected.cron ? selected.cron : prev.cronExpression
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const url = editingId ? `${API_BASE}/schedules/${editingId}` : `${API_BASE}/schedules`;
      const method = editingId ? 'PUT' : 'POST';

      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || 'Error al guardar la regla');
      }

      showNotification(editingId ? 'Regla actualizada con éxito' : 'Regla de escaneo recurrente creada exitosamente');
      setIsFormOpen(false);
      resetForm();
      fetchSchedules();
    } catch (err) {
      showNotification(err.message, false);
    }
  };

  const handleToggle = async (id) => {
    try {
      const res = await fetch(`${API_BASE}/schedules/${id}/toggle`, {
        method: 'PATCH'
      });
      if (!res.ok) throw new Error('Error al cambiar estado de la regla');
      const updated = await res.json();
      showNotification(`Regla ${updated.isActive ? 'Reanudada' : 'Pausada'} correctamente`);
      fetchSchedules();
    } catch (err) {
      showNotification(err.message, false);
    }
  };

  const handleRunNow = async (id) => {
    try {
      const res = await fetch(`${API_BASE}/schedules/${id}/run`, {
        method: 'POST'
      });
      if (!res.ok) throw new Error('Error al ejecutar el escaneo inmediato');
      const data = await res.json();
      showNotification(`Escaneo iniciado exitosamente (ID Escaneo: ${data.scan.id})`);
      fetchSchedules();
    } catch (err) {
      showNotification(err.message, false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('¿Está seguro de eliminar esta regla de programación?')) return;
    try {
      const res = await fetch(`${API_BASE}/schedules/${id}`, {
        method: 'DELETE'
      });
      if (!res.ok) throw new Error('Error al eliminar la regla');
      showNotification('Regla eliminada correctamente');
      fetchSchedules();
    } catch (err) {
      showNotification(err.message, false);
    }
  };

  const handleEdit = (rule) => {
    setEditingId(rule.id);
    setFormData({
      name: rule.name,
      target: rule.target,
      preset: rule.preset || 'custom',
      cronExpression: rule.cronExpression,
      isActive: rule.isActive
    });
    setIsFormOpen(true);
  };

  const resetForm = () => {
    setEditingId(null);
    setFormData({
      name: '',
      target: '',
      preset: 'daily',
      cronExpression: '0 0 * * *',
      isActive: true
    });
  };

  const activeCount = schedules.filter(s => s.isActive).length;
  const pausedCount = schedules.filter(s => !s.isActive).length;

  return (
    <div className="schedule-dashboard">
      <header className="dashboard-header">
        <div>
          <div className="badge-sysadmin">HU-011 • SysAdmin Operations</div>
          <h1>Programación de Escaneos Recurrentes</h1>
          <p className="subtitle">
            Gestión automatizada de escaneos periódicos (Diarios, Semanales, Mensuales o Cron) sin intervención manual.
          </p>
        </div>
        <button
          className="btn btn-primary"
          onClick={() => { resetForm(); setIsFormOpen(true); }}
        >
          + Nueva Regla de Escaneo
        </button>
      </header>

      {actionMessage && (
        <div className={`toast-notification ${actionMessage.isSuccess ? 'success' : 'error'}`}>
          {actionMessage.text}
        </div>
      )}

      {/* Stats Widgets */}
      <div className="stats-grid">
        <div className="stat-card">
          <span className="stat-title">Total Reglas</span>
          <span className="stat-value">{schedules.length}</span>
        </div>
        <div className="stat-card active-card">
          <span className="stat-title">Activas / En Ejecución</span>
          <span className="stat-value text-success">{activeCount}</span>
        </div>
        <div className="stat-card paused-card">
          <span className="stat-title">Pausadas</span>
          <span className="stat-value text-warning">{pausedCount}</span>
        </div>
      </div>

      {/* Modal / Form inline */}
      {isFormOpen && (
        <div className="form-modal-overlay">
          <div className="form-card">
            <h2>{editingId ? 'Editar Regla de Agendamiento' : 'Crear Regla de Escaneo Recurrente'}</h2>
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>Nombre de la Regla</label>
                <input
                  type="text"
                  required
                  placeholder="ej. Escaneo Diario Servidores Web"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label>Objetivo (Target / Subred / Hostname)</label>
                <input
                  type="text"
                  required
                  placeholder="ej. 192.168.1.0/24 o backend.local"
                  value={formData.target}
                  onChange={(e) => setFormData({ ...formData, target: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label>Frecuencia / Preset</label>
                <select value={formData.preset} onChange={handlePresetChange}>
                  {PRESETS_INFO.map(p => (
                    <option key={p.id} value={p.id}>{p.label}</option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label>Expresión Cron (`min hora día mes día_semana`)</label>
                <input
                  type="text"
                  required
                  placeholder="0 0 * * *"
                  value={formData.cronExpression}
                  onChange={(e) => setFormData({ ...formData, cronExpression: e.target.value })}
                />
                <small className="help-text">
                  Preset activo o expresión Cron personalizada en formato unix node-cron.
                </small>
              </div>

              <div className="form-group checkbox-group">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={formData.isActive}
                    onChange={(e) => setFormData({ ...formData, isActive: e.target.checked })}
                  />
                  <span>Activar regla inmediatamente al guardar</span>
                </label>
              </div>

              <div className="form-actions">
                <button type="button" className="btn btn-secondary" onClick={() => setIsFormOpen(false)}>
                  Cancelar
                </button>
                <button type="submit" className="btn btn-primary">
                  {editingId ? 'Guardar Cambios' : 'Crear Regla'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Rules Table */}
      <div className="table-container">
        {loading ? (
          <div className="loading-spinner">Cargando reglas de agendamiento...</div>
        ) : error ? (
          <div className="error-box">Error al cargar datos del backend: {error}</div>
        ) : schedules.length === 0 ? (
          <div className="empty-state">
            <p>No existen reglas de escaneo recurrente configuradas.</p>
            <button className="btn btn-primary btn-sm" onClick={() => setIsFormOpen(true)}>
              + Crear la primera regla
            </button>
          </div>
        ) : (
          <table className="rules-table">
            <thead>
              <tr>
                <th>Estado</th>
                <th>Nombre de Regla</th>
                <th>Objetivo</th>
                <th>Frecuencia (Cron)</th>
                <th>Última Ejecución</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {schedules.map(rule => (
                <tr key={rule.id} className={!rule.isActive ? 'row-paused' : ''}>
                  <td>
                    <span className={`status-badge ${rule.isActive ? 'status-active' : 'status-paused'}`}>
                      <span className="dot"></span>
                      {rule.isActive ? 'ACTIVO' : 'PAUSADO'}
                    </span>
                  </td>
                  <td>
                    <div className="rule-name">{rule.name}</div>
                    <div className="rule-id">{rule.id.substring(0, 8)}...</div>
                  </td>
                  <td><code className="target-code">{rule.target}</code></td>
                  <td>
                    <span className="cron-badge">{rule.preset ? rule.preset.toUpperCase() : 'CUSTOM'}</span>
                    <code className="cron-code">{rule.cronExpression}</code>
                  </td>
                  <td>
                    {rule.lastRunAt ? (
                      new Date(rule.lastRunAt).toLocaleString()
                    ) : (
                      <span className="text-muted">Pendiente primera ejecución</span>
                    )}
                  </td>
                  <td>
                    <div className="action-buttons">
                      <button
                        className={`btn btn-xs ${rule.isActive ? 'btn-warning' : 'btn-success'}`}
                        onClick={() => handleToggle(rule.id)}
                        title={rule.isActive ? 'Pausar regla' : 'Reanudar regla'}
                      >
                        {rule.isActive ? '⏸ Pausar' : '▶ Reanudar'}
                      </button>
                      <button
                        className="btn btn-xs btn-info"
                        onClick={() => handleRunNow(rule.id)}
                        title="Ejecutar escaneo ahora mismo (HU-009)"
                      >
                        ⚡ Ejecutar Ahora
                      </button>
                      <button
                        className="btn btn-xs btn-secondary"
                        onClick={() => handleEdit(rule)}
                        title="Editar regla"
                      >
                        ✏️ Editar
                      </button>
                      <button
                        className="btn btn-xs btn-danger"
                        onClick={() => handleDelete(rule.id)}
                        title="Eliminar regla"
                      >
                        🗑️
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
