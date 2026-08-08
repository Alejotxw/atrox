import React, { useState } from 'react';
import { KeyRound, Lock, ArrowRight, ArrowLeft, Loader2, AlertTriangle, QrCode, ShieldCheck } from 'lucide-react';
import QRCode from 'qrcode';
import { loginApi, verifyMfaApi, getMfaSetupApi, setAuthToken, describeError } from '../../lib/api';
import uideLogo from '../../../image/UIDE.png';

interface LoginFormProps {
  onSuccess: (username: string, role: string) => void;
  onBack?: () => void;
}

export default function LoginForm({ onSuccess, onBack }: LoginFormProps) {
  const [step, setStep] = useState<1 | 2>(1);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [totpCode, setTotpCode] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showSetupModal, setShowSetupModal] = useState(false);
  const [setupData, setSetupData] = useState<{ secret: string; otpauth_url: string } | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);

  // Paso 1: Autenticación de credenciales
  const handlePrimaryLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await loginApi(username, password);
      if (res.mfa_required && res.mfa_token) {
        setMfaToken(res.mfa_token);
        setStep(2);
      } else if (res.session_token && res.user) {
        // Cuentas regulares (aprobadas desde una solicitud de acceso): sin TOTP, sesión directa
        setAuthToken(res.session_token);
        onSuccess(res.user.username, res.user.role);
      }
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
      onSuccess(res.user.username, res.user.role);
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
      setQrDataUrl(null);
      // El QR se genera 100% en el cliente (nunca se envía el secreto a un
      // tercero) — sirve al propio otpauth_url ya devuelto por el backend.
      const dataUrl = await QRCode.toDataURL(data.otpauth_url, {
        width: 220,
        margin: 1,
        color: { dark: '#0B1121', light: '#FFFFFF' },
      });
      setQrDataUrl(dataUrl);
    } catch (err: any) {
      alert("Error cargando configuración MFA: " + describeError(err));
    }
  };

  return (
    <div className="min-h-screen bg-white flex items-center justify-center p-4 relative overflow-hidden font-sans">
      {/* Fondo: patrón de puntos + gradientes suaves, mismo lenguaje visual de la landing */}
      <div
        aria-hidden
        className="absolute inset-0 -z-10 [background-image:radial-gradient(circle,#7A1C3E0d_1px,transparent_1px)] [background-size:28px_28px] [mask-image:radial-gradient(ellipse_70%_60%_at_50%_40%,black_30%,transparent_100%)]"
      />
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-[#7A1C3E]/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-[#D4AF37]/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-6 sm:p-8 shadow-xl shadow-slate-900/5 relative z-10">

        {onBack && (
          <button
            onClick={onBack}
            className="flex items-center gap-1.5 text-xs font-semibold text-slate-500 hover:text-[#7A1C3E] mb-6 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Volver al inicio
          </button>
        )}

        {/* Header Branding */}
        <div className="flex items-center gap-3 mb-8">
          <img src={uideLogo} alt="UIDE — Powered by Arizona State University" className="h-10 w-auto shrink-0" />
          <span aria-hidden className="w-px h-9 bg-slate-200 shrink-0" />
          <div>
            <h1 className="text-slate-900 font-bold text-xl leading-none tracking-tight">ATROX</h1>
            <p className="text-xs text-[#7A1C3E] font-semibold tracking-wide">Panel Operativo SysAdmin</p>
          </div>
        </div>

        {/* Dynamic Title per Step */}
        <div className="mb-6">
          <h2 className="text-lg font-bold text-slate-900 mb-1">
            {step === 1 ? 'Iniciar Sesión' : 'Segundo Factor (MFA / TOTP)'}
          </h2>
          <p className="text-xs text-slate-500">
            {step === 1
              ? 'Ingrese sus credenciales para continuar'
              : `Ingrese el código de 6 dígitos enviado a su app autenticadora para ${username}`}
          </p>
        </div>

        {/* Error Alert Box */}
        {error && (
          <div className="mb-6 bg-red-50 border border-red-200 text-red-700 p-3.5 rounded-xl text-xs flex items-start gap-3">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <div className="flex-1 font-medium">{error}</div>
          </div>
        )}

        {/* Step 1: Username + Password */}
        {step === 1 && (
          <form onSubmit={handlePrimaryLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wider mb-2">Usuario</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                  <KeyRound className="h-4 w-4 text-slate-400" />
                </div>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-800 focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent transition-all"
                  placeholder="Usuario"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wider mb-2">Contraseña</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                  <Lock className="h-4 w-4 text-slate-400" />
                </div>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-800 focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent transition-all"
                  placeholder="••••••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading || !username.trim() || !password.trim()}
              className="w-full mt-2 bg-[#7A1C3E] hover:bg-[#90244B] text-white py-3 rounded-xl font-semibold text-sm flex items-center justify-center gap-2 transition-all shadow-lg shadow-[#7A1C3E]/25 disabled:opacity-50 disabled:cursor-not-allowed"
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
                <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wider">Código TOTP (6 Dígitos)</label>
                <button
                  type="button"
                  onClick={handleFetchSetup}
                  className="text-xs text-[#7A1C3E] hover:underline flex items-center gap-1 font-medium"
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
                className="w-full py-3 bg-slate-50 border border-slate-200 rounded-xl text-center font-mono text-2xl tracking-[0.5em] text-slate-800 focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent transition-all"
                placeholder="000000"
              />
            </div>

            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => { setStep(1); setError(null); }}
                className="w-1/3 py-3 border border-slate-200 text-slate-600 hover:bg-slate-50 rounded-xl text-xs font-semibold transition-all"
              >
                Volver
              </button>
              <button
                type="submit"
                disabled={loading || totpCode.length !== 6}
                className="w-2/3 bg-[#7A1C3E] hover:bg-[#90244B] text-white py-3 rounded-xl font-semibold text-sm flex items-center justify-center gap-2 transition-all shadow-lg shadow-[#7A1C3E]/25 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <>Verificar y Entrar <ShieldCheck className="w-4 h-4" /></>}
              </button>
            </div>
          </form>
        )}

        {/* Modal con Secreto / Clave TOTP de Prueba para la demostración E2E */}
        {showSetupModal && setupData && (
          <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-in fade-in">
            <div className="bg-white border border-slate-200 rounded-2xl p-6 max-w-sm w-full space-y-4 text-center shadow-2xl">
              <div className="w-12 h-12 rounded-full bg-[#7A1C3E]/10 text-[#7A1C3E] mx-auto flex items-center justify-center border border-[#7A1C3E]/20">
                <QrCode className="w-6 h-6" />
              </div>
              <h3 className="text-slate-900 font-bold text-base">Configuración Inicial TOTP</h3>
              <p className="text-xs text-slate-500">
                Escanee este código con Google Authenticator, Authy o similar:
              </p>

              <div className="flex justify-center">
                {qrDataUrl ? (
                  <img
                    src={qrDataUrl}
                    alt="Código QR para configurar TOTP"
                    className="rounded-xl border border-slate-200 w-[220px] h-[220px]"
                  />
                ) : (
                  <div className="w-[220px] h-[220px] flex items-center justify-center bg-slate-50 rounded-xl border border-slate-200">
                    <Loader2 className="w-6 h-6 text-slate-400 animate-spin" />
                  </div>
                )}
              </div>

              <p className="text-xs text-slate-500">
                ¿No puede escanear? Ingrese esta clave manualmente:
              </p>

              <div className="bg-slate-50 p-3 rounded-xl border border-slate-200 font-mono text-xs text-[#7A1C3E] select-all break-all">
                {setupData.secret}
              </div>

              <button
                onClick={() => setShowSetupModal(false)}
                className="w-full bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold py-2.5 rounded-xl transition-all border border-slate-200"
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
