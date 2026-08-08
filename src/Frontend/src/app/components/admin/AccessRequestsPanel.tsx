import { useEffect, useState } from 'react';
import {
  Loader2,
  AlertTriangle,
  UserCheck,
  UserX,
  Clock,
  Copy,
  CheckCircle2,
  X,
} from 'lucide-react';
import {
  listAccessRequestsApi,
  approveAccessRequestApi,
  rejectAccessRequestApi,
  describeError,
  type AdminAccessRequest,
  type AccessRequestStatus,
} from '../../lib/api';

const STATUS_LABEL: Record<AccessRequestStatus, string> = {
  pending: 'Pendiente',
  approved: 'Aprobada',
  rejected: 'Rechazada',
};

const STATUS_BADGE: Record<AccessRequestStatus, string> = {
  pending: 'bg-[#D4AF37]/10 text-[#D4AF37] border-[#D4AF37]/30',
  approved: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  rejected: 'bg-red-500/10 text-red-400 border-red-500/30',
};

const FILTERS: { value: AccessRequestStatus | 'all'; label: string }[] = [
  { value: 'pending', label: 'Pendientes' },
  { value: 'approved', label: 'Aprobadas' },
  { value: 'rejected', label: 'Rechazadas' },
  { value: 'all', label: 'Todas' },
];

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('es-EC', { dateStyle: 'medium', timeStyle: 'short' });
}

export default function AccessRequestsPanel() {
  const [requests, setRequests] = useState<AdminAccessRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<AccessRequestStatus | 'all'>('pending');
  const [actioningId, setActioningId] = useState<string | null>(null);
  const [rejectingId, setRejectingId] = useState<string | null>(null);
  const [rejectReason, setRejectReason] = useState('');
  const [credentials, setCredentials] = useState<{ username: string; password: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await listAccessRequestsApi();
      setRequests(res.requests);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleApprove = async (id: string) => {
    setActioningId(id);
    try {
      const res = await approveAccessRequestApi(id);
      setCredentials({ username: res.account.username, password: res.temporary_password });
      await load();
    } catch (err) {
      alert('Error al aprobar la solicitud: ' + describeError(err));
    } finally {
      setActioningId(null);
    }
  };

  const handleConfirmReject = async () => {
    if (!rejectingId) return;
    setActioningId(rejectingId);
    try {
      await rejectAccessRequestApi(rejectingId, rejectReason.trim() || undefined);
      setRejectingId(null);
      setRejectReason('');
      await load();
    } catch (err) {
      alert('Error al rechazar la solicitud: ' + describeError(err));
    } finally {
      setActioningId(null);
    }
  };

  const visibleRequests = requests.filter((r) => filter === 'all' || r.status === filter);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        {FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => setFilter(f.value)}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
              filter === f.value
                ? 'bg-[#7A1C3E] border-[#7A1C3E] text-white'
                : 'bg-transparent border-slate-700 text-slate-400 hover:border-slate-600 hover:text-slate-200'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 p-3.5 rounded-xl text-xs flex items-center gap-3">
          <AlertTriangle className="w-4 h-4 shrink-0" /> {error}
        </div>
      )}

      <div className="bg-[#1E293B] border border-slate-700 rounded-xl overflow-hidden shadow-lg">
        {loading ? (
          <div className="flex items-center justify-center py-16 text-slate-500">
            <Loader2 className="w-6 h-6 animate-spin" />
          </div>
        ) : visibleRequests.length === 0 ? (
          <div className="py-16 text-center text-sm text-slate-500">No hay solicitudes en este estado.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-left text-[11px] uppercase tracking-wider text-slate-500">
                  <th className="px-4 py-3 font-semibold">Solicitante</th>
                  <th className="px-4 py-3 font-semibold">Organización / Rol</th>
                  <th className="px-4 py-3 font-semibold">Motivo</th>
                  <th className="px-4 py-3 font-semibold">Fecha</th>
                  <th className="px-4 py-3 font-semibold">Estado</th>
                  <th className="px-4 py-3 font-semibold text-right">Acciones</th>
                </tr>
              </thead>
              <tbody>
                {visibleRequests.map((r) => (
                  <tr key={r.id} className="border-b border-slate-800/60 last:border-0 hover:bg-white/[0.02]">
                    <td className="px-4 py-3.5">
                      <div className="font-semibold text-slate-200">{r.full_name}</div>
                      <div className="text-xs text-slate-500">{r.email}</div>
                    </td>
                    <td className="px-4 py-3.5 text-slate-300">
                      <div>{r.organization}</div>
                      <div className="text-xs text-slate-500">{r.role}</div>
                    </td>
                    <td className="px-4 py-3.5 text-slate-400 max-w-xs">
                      <p className="line-clamp-2">{r.reason}</p>
                      {r.status === 'rejected' && r.review_reason && (
                        <p className="text-xs text-red-400/80 mt-1">Motivo rechazo: {r.review_reason}</p>
                      )}
                    </td>
                    <td className="px-4 py-3.5 text-xs text-slate-500 whitespace-nowrap">
                      {formatDate(r.created_at)}
                    </td>
                    <td className="px-4 py-3.5">
                      <span
                        className={`inline-flex items-center gap-1 text-[11px] font-semibold px-2.5 py-1 rounded-full border ${STATUS_BADGE[r.status]}`}
                      >
                        {r.status === 'pending' && <Clock className="w-3 h-3" />}
                        {STATUS_LABEL[r.status]}
                      </span>
                    </td>
                    <td className="px-4 py-3.5">
                      {r.status === 'pending' && (
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleApprove(r.id)}
                            disabled={actioningId === r.id}
                            className="flex items-center gap-1.5 text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 px-3 py-1.5 rounded-lg transition-all disabled:opacity-50"
                          >
                            {actioningId === r.id ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <UserCheck className="w-3.5 h-3.5" />
                            )}
                            Aprobar
                          </button>
                          <button
                            onClick={() => setRejectingId(r.id)}
                            disabled={actioningId === r.id}
                            className="flex items-center gap-1.5 text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/30 hover:bg-red-500/20 px-3 py-1.5 rounded-lg transition-all disabled:opacity-50"
                          >
                            <UserX className="w-3.5 h-3.5" />
                            Rechazar
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal: motivo de rechazo */}
      {rejectingId && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#0F172A] border border-slate-700 rounded-2xl p-6 max-w-sm w-full space-y-4 shadow-2xl">
            <h3 className="text-white font-bold text-base">Rechazar solicitud</h3>
            <p className="text-xs text-slate-400">Motivo opcional (visible solo para el equipo administrador):</p>
            <textarea
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              rows={3}
              maxLength={500}
              className="w-full px-3.5 py-2.5 bg-[#0B1121] border border-slate-700 rounded-xl text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent transition-all resize-none"
              placeholder="Ej: correo institucional no verificable"
            />
            <div className="flex items-center gap-3">
              <button
                onClick={() => { setRejectingId(null); setRejectReason(''); }}
                className="w-1/2 py-2.5 border border-slate-700 text-slate-300 hover:bg-slate-800 rounded-xl text-xs font-semibold transition-all"
              >
                Cancelar
              </button>
              <button
                onClick={handleConfirmReject}
                disabled={actioningId === rejectingId}
                className="w-1/2 bg-red-600 hover:bg-red-700 text-white py-2.5 rounded-xl text-xs font-semibold transition-all disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {actioningId === rejectingId ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Confirmar rechazo'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: credenciales generadas (se muestran una sola vez) */}
      {credentials && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#0F172A] border border-slate-700 rounded-2xl p-6 max-w-sm w-full space-y-4 text-center shadow-2xl relative">
            <button
              onClick={() => { setCredentials(null); setCopied(false); }}
              aria-label="Cerrar"
              className="absolute top-4 right-4 text-slate-500 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
            <div className="w-12 h-12 rounded-full bg-emerald-500/10 text-emerald-400 mx-auto flex items-center justify-center border border-emerald-500/30">
              <CheckCircle2 className="w-6 h-6" />
            </div>
            <h3 className="text-white font-bold text-base">Cuenta creada</h3>
            <p className="text-xs text-slate-400">
              Comparte estas credenciales con el solicitante — no se enviarán por correo y no volverán a mostrarse.
            </p>
            <div className="bg-[#0B1121] border border-slate-800 rounded-xl p-4 space-y-3 text-left">
              <div>
                <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Usuario</p>
                <p className="font-mono text-sm text-slate-200 select-all">{credentials.username}</p>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Contraseña temporal</p>
                <p className="font-mono text-sm text-[#D4AF37] select-all break-all">{credentials.password}</p>
              </div>
            </div>
            <button
              onClick={() => {
                navigator.clipboard.writeText(`Usuario: ${credentials.username}\nContraseña: ${credentials.password}`);
                setCopied(true);
              }}
              className="w-full flex items-center justify-center gap-2 bg-[#7A1C3E] hover:bg-[#90244B] text-white text-xs font-semibold py-2.5 rounded-xl transition-all"
            >
              {copied ? <CheckCircle2 className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              {copied ? 'Copiado' : 'Copiar credenciales'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
