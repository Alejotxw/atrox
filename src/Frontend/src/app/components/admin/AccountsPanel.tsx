import { Fragment, useEffect, useState } from 'react';
import {
  Loader2,
  AlertTriangle,
  Ban,
  RotateCcw,
  Trash2,
  ShieldAlert,
  Flag,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import {
  listAccountsApi,
  suspendAccountApi,
  reactivateAccountApi,
  deleteAccountApi,
  warnAccountApi,
  reportAccountApi,
  describeError,
  type Account,
  type AccountStatus,
  type ModerationNoteKind,
} from '../../lib/api';

const STATUS_LABEL: Record<AccountStatus, string> = {
  active: 'Activa',
  suspended: 'Suspendida',
  deleted: 'Eliminada',
};

const STATUS_BADGE: Record<AccountStatus, string> = {
  active: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  suspended: 'bg-[#D4AF37]/10 text-[#D4AF37] border-[#D4AF37]/30',
  deleted: 'bg-red-500/10 text-red-400 border-red-500/30',
};

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('es-EC', { dateStyle: 'medium', timeStyle: 'short' });
}

export default function AccountsPanel() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actioningId, setActioningId] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [reasonModal, setReasonModal] = useState<{ accountId: string; kind: ModerationNoteKind } | null>(null);
  const [reason, setReason] = useState('');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await listAccountsApi();
      setAccounts(res.accounts);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const runAction = async (id: string, action: () => Promise<Account>) => {
    setActioningId(id);
    try {
      await action();
      await load();
    } catch (err) {
      alert('Error al procesar la acción: ' + describeError(err));
    } finally {
      setActioningId(null);
    }
  };

  const handleSuspend = (account: Account) => {
    if (!window.confirm(`¿Suspender la cuenta de ${account.full_name} (${account.username})?`)) return;
    runAction(account.id, () => suspendAccountApi(account.id));
  };

  const handleReactivate = (account: Account) => {
    runAction(account.id, () => reactivateAccountApi(account.id));
  };

  const handleDelete = (account: Account) => {
    if (!window.confirm(`¿Eliminar la cuenta de ${account.full_name} (${account.username})? Esta acción no se puede deshacer.`)) return;
    runAction(account.id, () => deleteAccountApi(account.id));
  };

  const handleConfirmReason = async () => {
    if (!reasonModal || reason.trim().length < 3) return;
    setActioningId(reasonModal.accountId);
    try {
      if (reasonModal.kind === 'warning') {
        await warnAccountApi(reasonModal.accountId, reason.trim());
      } else {
        await reportAccountApi(reasonModal.accountId, reason.trim());
      }
      setReasonModal(null);
      setReason('');
      await load();
    } catch (err) {
      alert('Error al registrar: ' + describeError(err));
    } finally {
      setActioningId(null);
    }
  };

  return (
    <div className="space-y-5">
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
        ) : accounts.length === 0 ? (
          <div className="py-16 text-center text-sm text-slate-500">
            Aún no hay cuentas. Se crean al aprobar una solicitud de acceso.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-left text-[11px] uppercase tracking-wider text-slate-500">
                  <th className="px-4 py-3 font-semibold">Cuenta</th>
                  <th className="px-4 py-3 font-semibold">Organización / Rol</th>
                  <th className="px-4 py-3 font-semibold">Estado</th>
                  <th className="px-4 py-3 font-semibold">Historial</th>
                  <th className="px-4 py-3 font-semibold text-right">Acciones</th>
                </tr>
              </thead>
              <tbody>
                {accounts.map((account) => (
                  <Fragment key={account.id}>
                    <tr className="border-b border-slate-800/60 hover:bg-white/[0.02]">
                      <td className="px-4 py-3.5">
                        <div className="font-semibold text-slate-200">{account.full_name}</div>
                        <div className="text-xs text-slate-500 font-mono">{account.username} · {account.email}</div>
                      </td>
                      <td className="px-4 py-3.5 text-slate-300">
                        <div>{account.organization}</div>
                        <div className="text-xs text-slate-500">{account.role}</div>
                      </td>
                      <td className="px-4 py-3.5">
                        <span
                          className={`inline-flex items-center text-[11px] font-semibold px-2.5 py-1 rounded-full border ${STATUS_BADGE[account.status]}`}
                        >
                          {STATUS_LABEL[account.status]}
                        </span>
                      </td>
                      <td className="px-4 py-3.5">
                        {account.moderation_notes.length === 0 ? (
                          <span className="text-xs text-slate-600">Sin incidencias</span>
                        ) : (
                          <button
                            onClick={() => setExpandedId(expandedId === account.id ? null : account.id)}
                            className="flex items-center gap-1 text-xs font-semibold text-[#D4AF37] hover:underline"
                          >
                            {expandedId === account.id ? (
                              <ChevronDown className="w-3.5 h-3.5" />
                            ) : (
                              <ChevronRight className="w-3.5 h-3.5" />
                            )}
                            {account.moderation_notes.length} nota(s)
                          </button>
                        )}
                      </td>
                      <td className="px-4 py-3.5">
                        <div className="flex items-center justify-end gap-1.5 flex-wrap">
                          <button
                            onClick={() => setReasonModal({ accountId: account.id, kind: 'warning' })}
                            disabled={actioningId === account.id}
                            title="Advertir"
                            className="p-1.5 rounded-lg bg-[#D4AF37]/10 text-[#D4AF37] border border-[#D4AF37]/30 hover:bg-[#D4AF37]/20 transition-all disabled:opacity-50"
                          >
                            <ShieldAlert className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => setReasonModal({ accountId: account.id, kind: 'report' })}
                            disabled={actioningId === account.id}
                            title="Reportar por uso fraudulento"
                            className="p-1.5 rounded-lg bg-orange-500/10 text-orange-400 border border-orange-500/30 hover:bg-orange-500/20 transition-all disabled:opacity-50"
                          >
                            <Flag className="w-3.5 h-3.5" />
                          </button>
                          {account.status === 'active' && (
                            <button
                              onClick={() => handleSuspend(account)}
                              disabled={actioningId === account.id}
                              title="Suspender"
                              className="p-1.5 rounded-lg bg-slate-700/40 text-slate-300 border border-slate-600 hover:bg-slate-700 transition-all disabled:opacity-50"
                            >
                              <Ban className="w-3.5 h-3.5" />
                            </button>
                          )}
                          {account.status === 'suspended' && (
                            <button
                              onClick={() => handleReactivate(account)}
                              disabled={actioningId === account.id}
                              title="Reactivar"
                              className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition-all disabled:opacity-50"
                            >
                              <RotateCcw className="w-3.5 h-3.5" />
                            </button>
                          )}
                          {account.status !== 'deleted' && (
                            <button
                              onClick={() => handleDelete(account)}
                              disabled={actioningId === account.id}
                              title="Eliminar"
                              className="p-1.5 rounded-lg bg-red-500/10 text-red-400 border border-red-500/30 hover:bg-red-500/20 transition-all disabled:opacity-50"
                            >
                              {actioningId === account.id ? (
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                              ) : (
                                <Trash2 className="w-3.5 h-3.5" />
                              )}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                    {expandedId === account.id && account.moderation_notes.length > 0 && (
                      <tr className="border-b border-slate-800/60 bg-black/20">
                        <td colSpan={5} className="px-4 py-3">
                          <div className="space-y-2">
                            {account.moderation_notes.map((note) => (
                              <div key={note.id} className="flex items-start gap-3 text-xs">
                                <span
                                  className={`shrink-0 mt-0.5 font-semibold px-2 py-0.5 rounded-full border ${
                                    note.kind === 'report'
                                      ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                                      : 'bg-[#D4AF37]/10 text-[#D4AF37] border-[#D4AF37]/30'
                                  }`}
                                >
                                  {note.kind === 'report' ? 'Reporte' : 'Advertencia'}
                                </span>
                                <div className="flex-1">
                                  <p className="text-slate-300">{note.reason}</p>
                                  <p className="text-slate-600 mt-0.5">
                                    {note.created_by} · {formatDate(note.created_at)}
                                  </p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal: motivo de advertencia/reporte */}
      {reasonModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#0F172A] border border-slate-700 rounded-2xl p-6 max-w-sm w-full space-y-4 shadow-2xl">
            <h3 className="text-white font-bold text-base">
              {reasonModal.kind === 'report' ? 'Reportar cuenta' : 'Advertir cuenta'}
            </h3>
            <p className="text-xs text-slate-400">
              Describe el motivo (uso fraudulento, incumplimiento de alcance, etc.). Queda en el historial de la
              cuenta.
            </p>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              maxLength={500}
              autoFocus
              className="w-full px-3.5 py-2.5 bg-[#0B1121] border border-slate-700 rounded-xl text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent transition-all resize-none"
              placeholder="Motivo (mínimo 3 caracteres)"
            />
            <div className="flex items-center gap-3">
              <button
                onClick={() => { setReasonModal(null); setReason(''); }}
                className="w-1/2 py-2.5 border border-slate-700 text-slate-300 hover:bg-slate-800 rounded-xl text-xs font-semibold transition-all"
              >
                Cancelar
              </button>
              <button
                onClick={handleConfirmReason}
                disabled={reason.trim().length < 3 || actioningId === reasonModal.accountId}
                className="w-1/2 bg-[#7A1C3E] hover:bg-[#90244B] text-white py-2.5 rounded-xl text-xs font-semibold transition-all disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {actioningId === reasonModal.accountId ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Confirmar'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
