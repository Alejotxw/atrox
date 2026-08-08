import React, { useState } from 'react';
import { Loader2, AlertTriangle, CheckCircle2, X, User, Mail, Building2, Briefcase, MessageSquare } from 'lucide-react';
import { submitAccessRequestApi, describeError } from '../../lib/api';

interface AccessRequestFormProps {
  onClose: () => void;
}

const initialFormState = {
  full_name: '',
  email: '',
  organization: '',
  role: '',
  reason: '',
};

export default function AccessRequestForm({ onClose }: AccessRequestFormProps) {
  const [form, setForm] = useState(initialFormState);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState(false);

  const updateField = (field: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setForm((prev) => ({ ...prev, [field]: e.target.value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await submitAccessRequestApi(form);
      setSubmitted(true);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4 z-50">
      <div className="w-full max-w-lg bg-white border border-slate-200 rounded-2xl shadow-2xl relative max-h-[90vh] overflow-y-auto">
        <button
          onClick={onClose}
          aria-label="Cerrar formulario"
          className="absolute top-4 right-4 text-slate-400 hover:text-slate-700 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="p-6 sm:p-8">
          {submitted ? (
            <div className="text-center py-6">
              <div className="w-14 h-14 rounded-full bg-emerald-50 text-emerald-600 mx-auto flex items-center justify-center border border-emerald-200 mb-4">
                <CheckCircle2 className="w-7 h-7" />
              </div>
              <h3 className="text-lg font-bold text-slate-900 mb-2">Solicitud registrada</h3>
              <p className="text-sm text-slate-500 mb-6">
                Tu solicitud fue enviada al equipo administrador de Atrox. Te contactaremos al correo
                proporcionado una vez que sea revisada.
              </p>
              <button
                onClick={onClose}
                className="bg-[#7A1C3E] hover:bg-[#90244B] text-white px-6 py-2.5 rounded-xl font-semibold text-sm transition-all"
              >
                Cerrar
              </button>
            </div>
          ) : (
            <>
              <h3 className="text-lg font-bold text-slate-900 mb-1">Solicitar acceso a Atrox</h3>
              <p className="text-xs text-slate-500 mb-6">
                Completa el formulario. Un administrador revisará tu solicitud manualmente.
              </p>

              {error && (
                <div className="mb-5 bg-red-50 border border-red-200 text-red-700 p-3.5 rounded-xl text-xs flex items-start gap-3">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                  <div className="flex-1 font-medium">{error}</div>
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wider mb-2">Nombre completo</label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                      <User className="h-4 w-4 text-slate-400" />
                    </div>
                    <input
                      type="text"
                      required
                      minLength={2}
                      value={form.full_name}
                      onChange={updateField('full_name')}
                      className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-800 focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent transition-all"
                      placeholder="Ana Torres"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wider mb-2">Correo</label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                      <Mail className="h-4 w-4 text-slate-400" />
                    </div>
                    <input
                      type="email"
                      required
                      value={form.email}
                      onChange={updateField('email')}
                      className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-800 focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent transition-all"
                      placeholder="nombre@uide.edu.ec"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wider mb-2">Organización</label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                        <Building2 className="h-4 w-4 text-slate-400" />
                      </div>
                      <input
                        type="text"
                        required
                        minLength={2}
                        value={form.organization}
                        onChange={updateField('organization')}
                        className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-800 focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent transition-all"
                        placeholder="UIDE - Ingeniería"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wider mb-2">Rol</label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                        <Briefcase className="h-4 w-4 text-slate-400" />
                      </div>
                      <input
                        type="text"
                        required
                        minLength={2}
                        value={form.role}
                        onChange={updateField('role')}
                        className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-800 focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent transition-all"
                        placeholder="Estudiante"
                      />
                    </div>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wider mb-2">Motivo de la solicitud</label>
                  <div className="relative">
                    <div className="absolute top-3 left-0 pl-3.5 flex items-start pointer-events-none">
                      <MessageSquare className="h-4 w-4 text-slate-400" />
                    </div>
                    <textarea
                      required
                      minLength={10}
                      maxLength={2000}
                      rows={3}
                      value={form.reason}
                      onChange={updateField('reason')}
                      className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-800 focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent transition-all resize-none"
                      placeholder="Describe para qué necesitas acceso a la plataforma"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full mt-2 bg-[#7A1C3E] hover:bg-[#90244B] text-white py-3 rounded-xl font-semibold text-sm flex items-center justify-center gap-2 transition-all shadow-lg shadow-[#7A1C3E]/20 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Enviar solicitud'}
                </button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
