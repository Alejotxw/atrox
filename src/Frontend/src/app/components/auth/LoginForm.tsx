import React, { useState } from 'react';
import { ShieldAlert, KeyRound, Lock, ArrowRight, Loader2, AlertTriangle, QrCode, CheckCircle2, ShieldCheck } from 'lucide-react';
import { loginApi, verifyMfaApi, getMfaSetupApi, setAuthToken, describeError } from '../../lib/api';

interface LoginFormProps {
  onSuccess: (username: string) => void;
}

export default function LoginForm({ onSuccess }: LoginFormProps) {
  const [step, setStep] = useState<1 | 2>(1);
  const [username, setUsername] = useState('sysadmin');
  const [password, setPassword] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [totpCode, setTotpCode] = useState('');
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showSetupModal, setShowSetupModal] = useState(false);
  const [setupData, setSetupData] = useState<{ secret: string; otpauth_url: string } | null>(null);

  // Paso 1: Autenticación de credenciales
  const handlePrimaryLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await loginApi(username, password);
      setMfaToken(res.mfa_token);
      setStep(2);
    } catch (err: any) {
      setError(describeError(err));
    } finally {
      setLoading(false);
    }
  };

  // Paso 2: Verificación de código TOTP (6 dígitos)
  const handleMfaVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpCode.trim() || totpCode.length !== 6) return;

    setLoading(true);
    setError(null);
    try {
      const res = await verifyMfaApi(mfaToken, totpCode);
      setAuthToken(res.session_token);
      onSuccess(res.user.username);
    } catch (err: any) {
      setError(describeError(err));
    } finally {
      setLoading(false);
    }
  };

  const handleFetchSetup = async () => {
    try {
      const data = await getMfaSetupApi();
      setSetupData({ secret: data.secret, otpauth_url: data.otpauth_url });
      setShowSetupModal(true);
    } catch (err: any) {
      alert("Error cargando configuración MFA: " + describeError(err));
    }
  };

  return (
    <div className="min-h-screen bg-[#090D16] flex items-center justify-center p-4 relative overflow-hidden font-sans">
      {/* Background Decorator Gradients */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-[#7A1C3E]/20 rounded-full blur-3xl pointer-events-none"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-900/15 rounded-full blur-3xl pointer-events-none"></div>

      <div className="w-full max-w-md bg-[#0F172A]/90 backdrop-blur-xl border border-slate-800 rounded-2xl p-8 shadow-2xl relative z-10">
        
        {/* Header Branding */}
        <div className="flex items-center gap-4 mb-8">
          <div className="w-12 h-12 rounded-xl bg-[#7A1C3E] flex items-center justify-center shadow-lg shadow-[#7A1C3E]/30">
            <ShieldAlert className="text-white w-7 h-7" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl tracking-tight">ATROX</h1>
            <p className="text-xs text-[#D4AF37] font-medium tracking-wide">Panel Operativo SysAdmin</p>
          </div>
        </div>

        {/* Dynamic Title per Step */}
        <div className="mb-6">
          <h2 className="text-lg font-bold text-white mb-1">
            {step === 1 ? 'Iniciar Sesión' : 'Segundo Factor (MFA / TOTP)'}
          </h2>
          <p className="text-xs text-slate-400">
            {step === 1 
              ? 'Ingrese sus credenciales de administrador para continuar' 
              : `Ingrese el código de 6 dígitos enviado a su app autenticadora para ${username}`}
          </p>
        </div>

        {/* Error Alert Box */}
        {error && (
          <div className="mb-6 bg-red-500/10 border border-red-500/30 text-red-400 p-3.5 rounded-xl text-xs flex items-start gap-3">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <div className="flex-1 font-medium">{error}</div>
          </div>
        )}

        {/* Step 1: Username + Password */}
        {step === 1 && (
          <form onSubmit={handlePrimaryLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Usuario</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                  <KeyRound className="h-4 w-4 text-slate-500" />
                </div>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-[#0B1121] border border-slate-700 rounded-xl text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent transition-all"
                  placeholder="sysadmin"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Contraseña</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                  <Lock className="h-4 w-4 text-slate-500" />
                </div>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-[#0B1121] border border-slate-700 rounded-xl text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent transition-all"
                  placeholder="••••••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading || !username.trim() || !password.trim()}
              className="w-full mt-2 bg-[#7A1C3E] hover:bg-[#90244B] text-white py-3 rounded-xl font-semibold text-sm flex items-center justify-center gap-2 transition-all shadow-lg shadow-[#7A1C3E]/30 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <>Continuar <ArrowRight className="w-4 h-4" /></>}
            </button>
          </form>
        )}

        {/* Step 2: TOTP 6-digit Code */}
        {step === 2 && (
          <form onSubmit={handleMfaVerify} className="space-y-5">
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider">Código TOTP (6 Dígitos)</label>
                <button
                  type="button"
                  onClick={handleFetchSetup}
                  className="text-xs text-[#D4AF37] hover:underline flex items-center gap-1 font-medium"
                >
                  <QrCode className="w-3.5 h-3.5" /> Clave / QR Setup
                </button>
              </div>
              <input
                type="text"
                maxLength={6}
                autoFocus
                required
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                className="w-full py-3 bg-[#0B1121] border border-slate-700 rounded-xl text-center font-mono text-2xl tracking-[0.5em] text-white focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent transition-all"
                placeholder="000000"
              />
            </div>

            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => { setStep(1); setError(null); }}
                className="w-1/3 py-3 border border-slate-700 text-slate-300 hover:bg-slate-800 rounded-xl text-xs font-semibold transition-all"
              >
                Volver
              </button>
              <button
                type="submit"
                disabled={loading || totpCode.length !== 6}
                className="w-2/3 bg-[#7A1C3E] hover:bg-[#90244B] text-white py-3 rounded-xl font-semibold text-sm flex items-center justify-center gap-2 transition-all shadow-lg shadow-[#7A1C3E]/30 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <>Verificar y Entrar <ShieldCheck className="w-4 h-4" /></>}
              </button>
            </div>
          </form>
        )}

        {/* Modal con Secreto / Clave TOTP de Prueba para la demostración E2E */}
        {showSetupModal && setupData && (
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-in fade-in">
            <div className="bg-[#0F172A] border border-slate-700 rounded-2xl p-6 max-w-sm w-full space-y-4 text-center shadow-2xl">
              <div className="w-12 h-12 rounded-full bg-[#7A1C3E]/20 text-[#D4AF37] mx-auto flex items-center justify-center border border-[#7A1C3E]/40">
                <QrCode className="w-6 h-6" />
              </div>
              <h3 className="text-white font-bold text-base">Configuración Inicial TOTP</h3>
              <p className="text-xs text-slate-400">
                Escanee en su aplicación autenticadora (Google Authenticator / Authy) o copie la siguiente clave secreta Base32:
              </p>
              
              <div className="bg-[#0B1121] p-3 rounded-xl border border-slate-800 font-mono text-xs text-[#D4AF37] select-all break-all">
                {setupData.secret}
              </div>

              <p className="text-[11px] text-slate-500 italic">
                URI OTPAuth: {setupData.otpauth_url}
              </p>

              <button
                onClick={() => setShowSetupModal(false)}
                className="w-full bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold py-2.5 rounded-xl transition-all border border-slate-700"
              >
                Cerrar y Regresar
              </button>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
