import React, { useState } from 'react';
import {
  Radar,
  ScanLine,
  Cpu,
  FileText,
  Lock,
  ShieldCheck,
  ArrowRight,
  ClipboardCheck,
  UserCheck,
  KeyRound,
  Sparkles,
  LayoutGrid,
  Workflow,
  BadgeCheck,
} from 'lucide-react';
import AccessRequestForm from './AccessRequestForm';
import { useInView } from './useInView';
import uideLogo from '../../../image/UIDE.png';

interface LandingPageProps {
  onRequestLogin: () => void;
}

const STACK_BADGES = ['Nmap', 'Nuclei', 'LangGraph', 'AES-256-GCM', 'HMAC-SHA256'];

const FEATURES = [
  {
    icon: Radar,
    title: 'Descubrimiento de activos',
    description: 'Escaneo de puertos y servicios sobre el objetivo con Nmap, orquestado desde la cola de trabajos.',
  },
  {
    icon: ScanLine,
    title: 'Escaneo de vulnerabilidades',
    description: 'Nuclei corre miles de plantillas de la comunidad para detectar hallazgos accionables.',
  },
  {
    icon: Cpu,
    title: 'Análisis con IA',
    description:
      'Un agente basado en LangGraph correlaciona hallazgos, prioriza vectores de ataque y decide cuándo detener el análisis.',
    highlight: true,
  },
  {
    icon: FileText,
    title: 'Reportes ejecutivos y técnicos',
    description: 'Exporta resultados en PDF, listos para compartir con stakeholders o el equipo técnico.',
  },
  {
    icon: Lock,
    title: 'Cifrado en reposo',
    description: 'Hallazgos y credenciales sensibles se cifran con AES-256-GCM antes de persistirse.',
  },
  {
    icon: ShieldCheck,
    title: 'Auditoría firmada',
    description: 'Cada acción queda en un log inmutable firmado con HMAC-SHA256, verificable en cualquier momento.',
  },
];

const STEPS = [
  {
    icon: ClipboardCheck,
    title: 'Solicita acceso',
    description: 'Completa el formulario con tus datos y el motivo de tu solicitud.',
    details: ['Nombre y correo', 'Organización', 'Motivo'],
  },
  {
    icon: UserCheck,
    title: 'Revisión del administrador',
    description: 'El equipo administrador evalúa la solicitud y te contacta por correo.',
    details: ['Evaluación manual', 'Respuesta por correo'],
  },
  {
    icon: KeyRound,
    title: 'Ingresa con MFA',
    description: 'Una vez aprobado, accedes al panel operativo con doble factor de autenticación.',
    details: ['TOTP', 'Sesión segura'],
    arrival: true,
  },
];

function Reveal({
  children,
  className = '',
  delay = 0,
}: {
  children: React.ReactNode;
  className?: string;
  delay?: number;
}) {
  const { ref, inView } = useInView<HTMLDivElement>();
  return (
    <div
      ref={ref}
      style={{ transitionDelay: inView ? `${delay}ms` : '0ms' }}
      className={`transition-all duration-700 ease-out ${
        inView ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
      } ${className}`}
    >
      {children}
    </div>
  );
}

function SectionEyebrow({ icon: Icon, children }: { icon: React.ElementType; children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-bold tracking-wider uppercase text-[#7A1C3E] bg-[#7A1C3E]/10 px-3 py-1.5 rounded-full mb-4">
      <Icon className="w-3.5 h-3.5" /> {children}
    </span>
  );
}

function RequestAccessCta({ onClick, className = '' }: { onClick: () => void; className?: string }) {
  return (
    <button
      onClick={onClick}
      className={`bg-[#7A1C3E] hover:bg-[#90244B] text-white px-8 py-3.5 rounded-xl font-semibold text-sm flex items-center justify-center gap-2 transition-all shadow-lg shadow-[#7A1C3E]/25 hover:shadow-xl hover:shadow-[#7A1C3E]/30 hover:-translate-y-0.5 ${className}`}
    >
      Solicitar acceso <ArrowRight className="w-4 h-4" />
    </button>
  );
}

function ScanConsolePreview() {
  return (
    <div className="relative">
      <div
        aria-hidden
        className="absolute -inset-6 bg-gradient-to-tr from-[#7A1C3E]/20 via-[#D4AF37]/10 to-transparent blur-3xl rounded-[2rem]"
      />
      <div className="relative rounded-2xl bg-[#0B1121] border border-white/10 shadow-2xl shadow-[#7A1C3E]/10 overflow-hidden -rotate-1 hover:rotate-0 transition-transform duration-500">
        <div className="flex items-center gap-1.5 px-4 py-3 border-b border-white/5 bg-white/[0.03]">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
          <span className="w-2.5 h-2.5 rounded-full bg-amber-400/70" />
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/70" />
          <span className="ml-3 text-[11px] text-slate-500 font-mono">atrox — consola de escaneo</span>
        </div>
        <div className="p-5 font-mono text-[12.5px] leading-relaxed space-y-1.5">
          <p>
            <span className="text-[#D4AF37]">$</span>{' '}
            <span className="text-slate-300">atrox scan --target corp.internal.uide.edu.ec</span>
          </p>
          <p className="text-slate-500">[NMAP] 3 host(s) activo(s), 12 puerto(s) abiertos</p>
          <p className="text-red-400">[NUCLEI] [CRITICAL] Apache Path Traversal en 10.0.4.12</p>
          <p className="text-amber-400">[NUCLEI] [HIGH] Cabecera de seguridad ausente (X-Frame-Options)</p>
          <p className="text-slate-500">[IA] Correlacionando hallazgos…</p>
          <p className="text-[#D4AF37]">[IA] Vector propuesto: RCE vía CVE-2021-41773 · severidad 9.1</p>
          <p className="text-emerald-400">[REPORT] Reporte ejecutivo generado ✓</p>
          <p className="text-slate-300">
            <span className="text-[#D4AF37]">$</span>{' '}
            <span className="inline-block w-2 h-3.5 align-middle bg-slate-400 animate-pulse ml-0.5" />
          </p>
        </div>
      </div>

      {/* Chip flotante decorativo */}
      <div className="hidden sm:flex absolute -top-4 -right-4 items-center gap-2 bg-white border border-slate-100 rounded-xl px-3.5 py-2 shadow-lg rotate-2">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
        </span>
        <span className="text-xs font-semibold text-slate-700">Cola asíncrona en vivo</span>
      </div>
    </div>
  );
}

export default function LandingPage({ onRequestLogin }: LandingPageProps) {
  const [showRequestForm, setShowRequestForm] = useState(false);

  return (
    <div className="min-h-screen bg-white text-slate-800 font-sans overflow-x-hidden">
      {/* Header */}
      <header className="border-b border-slate-100 sticky top-0 bg-white/85 backdrop-blur-md z-30">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3 sm:gap-4 min-w-0">
            <img
              src={uideLogo}
              alt="UIDE — Powered by Arizona State University"
              className="h-8 sm:h-10 w-auto shrink-0"
            />
            <span aria-hidden className="hidden sm:block w-px h-8 bg-slate-200 shrink-0" />
            <div className="min-w-0">
              <h1 className="text-slate-900 font-bold text-lg leading-none tracking-tight">ATROX</h1>
              <p className="hidden sm:block text-[10px] text-[#7A1C3E] font-semibold tracking-wide whitespace-nowrap">
                Pentesting Asistido por IA
              </p>
            </div>
          </div>
          <button
            onClick={onRequestLogin}
            className="group relative flex items-center gap-2 pl-2 pr-3 sm:pr-4 py-1.5 rounded-full border border-slate-200 hover:border-transparent overflow-hidden transition-colors duration-300 shrink-0"
          >
            <span
              aria-hidden
              className="absolute inset-0 bg-gradient-to-r from-[#7A1C3E] to-[#5c1530] scale-x-0 group-hover:scale-x-100 origin-right transition-transform duration-300 ease-out -z-10"
            />
            <span className="w-7 h-7 rounded-full bg-[#7A1C3E]/10 group-hover:bg-white/15 flex items-center justify-center transition-colors duration-300">
              <KeyRound className="w-3.5 h-3.5 text-[#7A1C3E] group-hover:text-white transition-colors duration-300" />
            </span>
            <span className="text-sm font-semibold text-slate-700 group-hover:text-white transition-colors duration-300 whitespace-nowrap">
              Iniciar sesión
            </span>
          </button>
        </div>
      </header>

      {/* Hero */}
      <section className="relative">
        <div
          aria-hidden
          className="absolute inset-0 -z-10 [background-image:radial-gradient(circle,#7A1C3E0d_1px,transparent_1px)] [background-size:28px_28px] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,black_40%,transparent_100%)]"
        />
        <div className="max-w-6xl mx-auto px-4 sm:px-6 pt-16 sm:pt-20 pb-24 grid lg:grid-cols-2 gap-14 items-center">
          <div className="text-center lg:text-left">
            <span className="inline-flex items-center gap-1.5 text-xs font-bold tracking-wider uppercase text-[#7A1C3E] bg-[#7A1C3E]/10 px-3 py-1.5 rounded-full mb-6">
              <Sparkles className="w-3.5 h-3.5" /> Proyecto académico · UIDE
            </span>
            <h2 className="text-4xl sm:text-5xl xl:text-6xl font-extrabold text-slate-900 tracking-tight leading-[1.05] mb-6">
              Automatiza tu auditoría de{' '}
              <span className="bg-gradient-to-r from-[#7A1C3E] to-[#D4AF37] bg-clip-text text-transparent">
                seguridad ofensiva
              </span>
            </h2>
            <p className="text-base sm:text-lg text-slate-500 max-w-xl mx-auto lg:mx-0 mb-8">
              Atrox combina descubrimiento de activos, escaneo de vulnerabilidades y un agente de IA que
              analiza los hallazgos y propone vectores de ataque — todo desde un panel operativo centralizado.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center lg:justify-start gap-4 mb-10">
              <RequestAccessCta onClick={() => setShowRequestForm(true)} className="w-full sm:w-auto" />
              <a
                href="#funcionalidades"
                className="w-full sm:w-auto text-slate-600 hover:text-[#7A1C3E] px-8 py-3.5 rounded-xl font-semibold text-sm border border-slate-200 hover:border-[#7A1C3E]/40 transition-all text-center"
              >
                Conocer más
              </a>
            </div>
            <div className="flex flex-wrap items-center justify-center lg:justify-start gap-2">
              {STACK_BADGES.map((badge) => (
                <span
                  key={badge}
                  className="text-[11px] font-mono font-medium text-slate-500 border border-slate-200 rounded-full px-3 py-1"
                >
                  {badge}
                </span>
              ))}
            </div>
          </div>

          <Reveal delay={150}>
            <ScanConsolePreview />
          </Reveal>
        </div>
      </section>

      {/* Features */}
      <section id="funcionalidades" className="relative max-w-6xl mx-auto px-4 sm:px-6 pb-28">
        <div
          aria-hidden
          className="absolute top-0 left-1/2 -translate-x-1/2 w-[36rem] h-[36rem] bg-[#D4AF37]/[0.06] rounded-full blur-3xl -z-10"
        />
        <Reveal className="text-center mb-14">
          <SectionEyebrow icon={LayoutGrid}>Capacidades de la plataforma</SectionEyebrow>
          <h3 className="text-2xl sm:text-3xl font-bold text-slate-900 mb-2">¿Qué hace Atrox?</h3>
          <p className="text-sm text-slate-500">Un flujo completo, del reconocimiento al reporte.</p>
        </Reveal>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
          {FEATURES.map(({ icon: Icon, title, description, highlight }, i) => (
            <Reveal key={title} delay={i * 60}>
              <div
                className={`group relative h-full flex flex-col overflow-hidden rounded-2xl border p-6 transition-all duration-300 hover:-translate-y-1 hover:shadow-lg ${
                  highlight
                    ? 'border-[#7A1C3E]/25 bg-gradient-to-b from-[#7A1C3E]/[0.04] to-transparent hover:border-[#7A1C3E]/50 hover:shadow-[#7A1C3E]/10'
                    : 'border-slate-200/80 hover:border-[#7A1C3E]/30 hover:shadow-[#7A1C3E]/5'
                }`}
              >
                {/* Acento superior: siempre visible en la card destacada, al hover en el resto */}
                <span
                  aria-hidden
                  className={`absolute top-0 left-0 right-0 h-0.5 origin-left transition-transform duration-300 bg-gradient-to-r from-[#7A1C3E] to-[#D4AF37] ${
                    highlight ? 'scale-x-100' : 'scale-x-0 group-hover:scale-x-100'
                  }`}
                />

                <div className="flex items-start justify-between mb-4">
                  <div
                    className={`w-11 h-11 rounded-xl flex items-center justify-center transition-transform duration-300 group-hover:scale-110 ${
                      highlight
                        ? 'bg-gradient-to-br from-[#7A1C3E] to-[#5c1530] text-white shadow-md shadow-[#7A1C3E]/20'
                        : 'bg-[#D4AF37]/15 text-[#7A1C3E]'
                    }`}
                  >
                    <Icon className="w-5 h-5" />
                  </div>
                  <span className="font-mono text-[11px] text-slate-300 pt-1">{String(i + 1).padStart(2, '0')}</span>
                </div>

                <div className="flex items-center gap-2 mb-2">
                  <h4 className="font-bold text-sm text-slate-900">{title}</h4>
                  {highlight && (
                    <span className="flex items-center gap-1 text-[9px] font-bold tracking-wider uppercase text-[#7A1C3E] bg-[#7A1C3E]/10 rounded-full px-2 py-0.5">
                      <Sparkles className="w-2.5 h-2.5" /> Diferenciador
                    </span>
                  )}
                </div>
                <p className="text-xs leading-relaxed text-slate-500">{description}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </section>

      {/* Cómo funciona */}
      <section className="relative bg-slate-50 border-y border-slate-100 overflow-hidden">
        <div
          aria-hidden
          className="absolute inset-0 -z-0 [background-image:radial-gradient(circle,#7A1C3E0d_1px,transparent_1px)] [background-size:24px_24px] [mask-image:radial-gradient(ellipse_70%_60%_at_50%_50%,black_20%,transparent_100%)]"
        />
        <div className="relative max-w-6xl mx-auto px-4 sm:px-6 py-20">
          <Reveal className="text-center mb-16">
            <SectionEyebrow icon={Workflow}>Proceso de acceso</SectionEyebrow>
            <h3 className="text-2xl sm:text-3xl font-bold text-slate-900 mb-2">¿Cómo obtengo acceso?</h3>
            <p className="text-sm text-slate-500 max-w-md mx-auto">
              Sin autoregistro abierto: cada solicitud pasa por revisión humana antes de habilitarse.
            </p>
          </Reveal>
          <div className="relative grid grid-cols-1 sm:grid-cols-3 gap-8 sm:gap-6 lg:gap-8">
            <div
              aria-hidden
              className="hidden sm:block absolute top-10 left-[16.6%] right-[16.6%] h-0.5 rounded-full bg-gradient-to-r from-[#7A1C3E]/50 via-[#D4AF37]/70 to-[#D4AF37]"
            />
            {STEPS.map(({ icon: Icon, title, description, details, arrival }, i) => (
              <Reveal key={title} delay={i * 120} className="relative">
                <div className="group relative h-full flex flex-col bg-white border border-slate-100 rounded-2xl px-6 pt-11 pb-6 text-center shadow-sm hover:shadow-xl hover:shadow-[#7A1C3E]/10 hover:-translate-y-1.5 transition-all duration-300">
                  <div
                    className={`absolute -top-7 left-1/2 -translate-x-1/2 w-14 h-14 rounded-full flex items-center justify-center font-bold text-sm text-white shadow-md ring-4 ring-slate-50 transition-transform duration-300 group-hover:scale-105 ${
                      arrival
                        ? 'bg-gradient-to-br from-[#7A1C3E] to-[#D4AF37] shadow-[#D4AF37]/40 ring-offset-0'
                        : 'bg-[#7A1C3E] shadow-[#7A1C3E]/30'
                    }`}
                  >
                    {i + 1}
                  </div>
                  <div className="w-11 h-11 rounded-xl bg-[#D4AF37]/15 text-[#7A1C3E] flex items-center justify-center mx-auto mb-4">
                    <Icon className="w-5 h-5" />
                  </div>
                  <h4 className="font-bold text-slate-900 text-sm mb-2">{title}</h4>
                  <p className="text-xs text-slate-500 max-w-xs mx-auto leading-relaxed mb-4">{description}</p>
                  <div className="mt-auto flex flex-wrap justify-center gap-1.5">
                    {details.map((detail) => (
                      <span
                        key={detail}
                        className="text-[10px] font-medium text-slate-500 bg-slate-50 border border-slate-100 rounded-full px-2.5 py-1"
                      >
                        {detail}
                      </span>
                    ))}
                  </div>
                </div>
              </Reveal>
            ))}
          </div>
          <Reveal delay={200} className="flex justify-center mt-14">
            <RequestAccessCta onClick={() => setShowRequestForm(true)} />
          </Reveal>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-[#0B1121] text-slate-400">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-14 grid grid-cols-1 sm:grid-cols-3 gap-10">
          <div className="sm:col-span-1">
            <div className="flex items-center gap-3 mb-4">
              <div className="bg-white rounded-lg p-1.5 shadow-sm">
                <img src={uideLogo} alt="UIDE — Powered by Arizona State University" className="h-7 w-auto" />
              </div>
              <span className="text-sm font-bold text-white tracking-tight">ATROX</span>
            </div>
            <p className="text-xs leading-relaxed max-w-xs">
              Plataforma de pentesting asistido por IA. Proyecto académico de la Universidad Internacional
              del Ecuador (UIDE).
            </p>
          </div>

          <div>
            <h5 className="text-[11px] font-bold uppercase tracking-wider text-slate-300 mb-3">Plataforma</h5>
            <ul className="space-y-2 text-xs">
              <li>
                <a href="#funcionalidades" className="hover:text-white transition-colors">
                  Funcionalidades
                </a>
              </li>
              <li>
                <button
                  onClick={() => setShowRequestForm(true)}
                  className="font-normal text-slate-400 hover:text-white transition-colors"
                >
                  Solicitar acceso
                </button>
              </li>
              <li>
                <button
                  onClick={onRequestLogin}
                  className="font-normal text-slate-400 hover:text-white transition-colors"
                >
                  Iniciar sesión
                </button>
              </li>
            </ul>
          </div>

          <div>
            <h5 className="text-[11px] font-bold uppercase tracking-wider text-slate-300 mb-3">Seguridad y stack</h5>
            <div className="flex flex-wrap gap-1.5">
              {STACK_BADGES.map((badge) => (
                <span
                  key={badge}
                  className="text-[10px] font-mono font-medium text-slate-400 border border-white/10 rounded-full px-2.5 py-1"
                >
                  {badge}
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="border-t border-white/5">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 py-5 flex flex-col sm:flex-row items-center justify-between gap-2">
            <p className="text-[11px] text-slate-500 flex items-center gap-1.5">
              <BadgeCheck className="w-3.5 h-3.5 text-[#D4AF37]" /> Uso exclusivo para pruebas de seguridad
              autorizadas.
            </p>
            <p className="text-[11px] text-slate-500">Atrox — Proyecto académico UIDE</p>
          </div>
        </div>
      </footer>

      {showRequestForm && <AccessRequestForm onClose={() => setShowRequestForm(false)} />}
    </div>
  );
}
