import { Check, Cpu, Network, ScanLine } from 'lucide-react';

export type AuditTaskId = 'discovery' | 'vulnscan' | 'vectorAnalysis';

export interface AuditTasks {
  discovery: boolean;
  vulnscan: boolean;
  vectorAnalysis: boolean;
}

export const DEFAULT_AUDIT_TASKS: AuditTasks = {
  discovery: true,
  vulnscan: true,
  vectorAnalysis: true,
};

const TASK_META: {
  id: AuditTaskId;
  title: string;
  description: string;
  why: string;
  eta: string;
  icon: typeof Network;
  dependsOn?: AuditTaskId;
}[] = [
  {
    id: 'discovery',
    title: 'Reconocimiento',
    description: 'Descubre qué hay encendido en la red.',
    why: 'Ideal si aún no conoces hosts ni puertos.',
    eta: '1–3 min',
    icon: Network,
  },
  {
    id: 'vulnscan',
    title: 'Escaneo de fallos',
    description: 'Busca vulnerabilidades conocidas (CVEs).',
    why: 'El núcleo de la auditoría de seguridad.',
    eta: '3–8 min',
    icon: ScanLine,
  },
  {
    id: 'vectorAnalysis',
    title: 'Análisis de impacto',
    description: 'Prioriza qué atacaría un adversario primero.',
    why: 'Útil para explicar el riesgo a no técnicos.',
    eta: '30–90 s',
    icon: Cpu,
    dependsOn: 'vulnscan',
  },
];

export function countSelectedTasks(tasks: AuditTasks): number {
  return (Object.keys(tasks) as AuditTaskId[]).filter((id) => tasks[id]).length;
}

export function estimateAuditLabel(tasks: AuditTasks): string {
  const n = countSelectedTasks(tasks);
  if (n === 0) return 'Selecciona al menos una tarea';
  if (tasks.discovery && tasks.vulnscan && tasks.vectorAnalysis) return 'Auditoría completa (~5–12 min)';
  if (tasks.vulnscan && tasks.vectorAnalysis) return 'Escaneo + impacto (~4–10 min)';
  if (tasks.discovery && tasks.vulnscan) return 'Recon + vulnerabilidades (~4–11 min)';
  if (tasks.discovery) return 'Solo reconocimiento (~1–3 min)';
  if (tasks.vulnscan) return 'Solo Nuclei (~3–8 min)';
  if (tasks.vectorAnalysis) return 'Solo impacto (requiere hallazgos)';
  return `${n} tarea(s) seleccionada(s)`;
}

export function selectedTaskTitles(tasks: AuditTasks): string[] {
  return TASK_META.filter((t) => tasks[t.id]).map((t) => t.title);
}

interface AuditTaskMarkerProps {
  tasks: AuditTasks;
  onChange: (next: AuditTasks) => void;
  disabled?: boolean;
  /** CTA inferior del paso 1 */
  onContinue?: () => void;
  compact?: boolean;
}

export default function AuditTaskMarker({
  tasks,
  onChange,
  disabled = false,
  onContinue,
  compact = false,
}: AuditTaskMarkerProps) {
  const toggle = (id: AuditTaskId) => {
    if (disabled) return;
    const next = { ...tasks, [id]: !tasks[id] };
    if (id === 'vulnscan' && !next.vulnscan) next.vectorAnalysis = false;
    if (id === 'vectorAnalysis' && next.vectorAnalysis) next.vulnscan = true;
    onChange(next);
  };

  const selected = countSelectedTasks(tasks);

  if (compact) {
    return (
      <div className="atrox-chip-row" aria-label="Tareas elegidas">
        {TASK_META.filter((t) => tasks[t.id]).map((t) => {
          const Icon = t.icon;
          return (
            <span key={t.id} className="atrox-chip">
              <Icon className="w-3 h-3" />
              {t.title}
            </span>
          );
        })}
        {selected === 0 && (
          <span className="text-[12px] text-[var(--ax-warn)]">Ninguna tarea seleccionada</span>
        )}
      </div>
    );
  }

  return (
    <section className="atrox-panel" aria-label="Paso 1: elegir tareas">
      <div className="atrox-hero-card border-b border-[var(--ax-border)]">
        <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--ax-brand)] mb-2">
          Paso 1 de 3
        </p>
        <h2 className="atrox-section-title text-[1.35rem]">¿Qué quieres revisar hoy?</h2>
        <p className="atrox-section-sub">
          Marca solo lo que necesites. Menos tareas = auditoría más rápida. Puedes cambiar esto
          después.
        </p>
      </div>

      <div className="p-4 sm:p-5">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <p className="text-[13px] text-[var(--ax-muted)]">
            <strong className="text-white">{selected}/3</strong> seleccionadas ·{' '}
            <span className="text-[var(--ax-text)]">{estimateAuditLabel(tasks)}</span>
          </p>
          <button
            type="button"
            disabled={disabled}
            onClick={() => onChange({ ...DEFAULT_AUDIT_TASKS })}
            className="atrox-btn-ghost text-[11px] px-3 py-1.5 disabled:opacity-40"
          >
            Marcar las 3
          </button>
        </div>

        <div className="atrox-tasks">
          {TASK_META.map((task) => {
            const isOn = tasks[task.id];
            const Icon = task.icon;
            const needsNuclei = task.dependsOn === 'vulnscan' && !tasks.vulnscan;

            return (
              <button
                key={task.id}
                type="button"
                disabled={disabled}
                onClick={() => toggle(task.id)}
                aria-pressed={isOn}
                className={`atrox-task-card ${isOn ? 'is-selected' : ''}`}
              >
                <div className="atrox-task-top">
                  <span className="atrox-task-icon">
                    <Icon className="w-4 h-4" />
                  </span>
                  <span className="atrox-task-check" aria-hidden>
                    {isOn ? <Check className="w-3 h-3" strokeWidth={3} /> : null}
                  </span>
                </div>
                <div className="min-w-0 flex-1">
                  <h3 className="text-[15px] font-semibold text-white mb-1">{task.title}</h3>
                  <p className="text-[13px] text-[var(--ax-text)]/80 leading-snug">{task.description}</p>
                  <p className="text-[12px] text-[var(--ax-muted)] mt-2 leading-snug">{task.why}</p>
                  <p className="text-[11px] text-[var(--ax-muted)] mt-3 font-mono">
                    Tiempo aprox. {task.eta}
                    {needsNuclei && !isOn ? ' · activa primero “Escaneo de fallos”' : ''}
                  </p>
                </div>
              </button>
            );
          })}
        </div>

        {onContinue && (
          <div className="atrox-task-footer">
            <p className="text-[12px] text-[var(--ax-muted)] max-w-md">
              Cuando termines de marcar, continúa para indicar el objetivo e iniciar.
            </p>
            <button
              type="button"
              disabled={disabled || selected === 0}
              onClick={onContinue}
              className="atrox-btn-primary atrox-btn-lg disabled:opacity-40"
            >
              Continuar al objetivo →
            </button>
          </div>
        )}
      </div>
    </section>
  );
}
