"""Interfaz de decisión IA — mockable para tests sin LLM real (HU-013)."""

from typing import Protocol

from atrox.ai.graph.state import (
    EvaluationResult,
    PentestGraphState,
    ProposedAction,
    ToolExecutionResult,
)


class PentestDecider(Protocol):
    """Contrato para el motor de decisión (LLM real o heurístico/simulado)."""

    def analyze_findings(self, state: PentestGraphState) -> str: ...

    def propose_action(self, state: PentestGraphState) -> ProposedAction: ...

    def evaluate(self, state: PentestGraphState) -> EvaluationResult: ...


class MockDecider:
    """Decider determinista para tests de recorrido completo."""

    def __init__(self, stop_after_cycles: int = 1) -> None:
        self._stop_after_cycles = stop_after_cycles
        self._cycles = 0

    def analyze_findings(self, state: PentestGraphState) -> str:
        count = len(state.get("findings", []))
        return f"Análisis simulado: {count} hallazgo(s) priorizados por severidad."

    def propose_action(self, state: PentestGraphState) -> ProposedAction:
        executed = state.get("executed_tools", [])
        target = state.get("target", "lab.target.local")

        if "nmap" not in executed:
            return {
                "tool": "nmap",
                "target": target,
                "rationale": "Descubrir superficie de ataque adicional",
                "params": {"port_range": "1-1024"},
            }
        return {
            "tool": "nuclei",
            "target": target,
            "rationale": "Validar vulnerabilidades en servicios expuestos",
            "params": {"severity": "critical,high"},
        }

    def evaluate(self, state: PentestGraphState) -> EvaluationResult:
        self._cycles += 1
        executed = state.get("executed_tools", [])

        if self._cycles >= self._stop_after_cycles and len(executed) >= 1:
            return {
                "sufficient": True,
                "continue_cycle": False,
                "reason": "Datos suficientes para correlación — condición de parada explícita",
            }

        if state.get("step_count", 0) >= state.get("max_steps", 5):
            return {
                "sufficient": False,
                "continue_cycle": False,
                "reason": "Límite máximo de pasos alcanzado",
            }

        return {
            "sufficient": False,
            "continue_cycle": True,
            "reason": "Se requiere escaneo adicional",
        }


class HeuristicDecider:
    """Decider heurístico sin LLM — útil para desarrollo y laboratorio."""

    def analyze_findings(self, state: PentestGraphState) -> str:
        findings = state.get("findings", [])
        if not findings:
            return "Sin hallazgos previos. Se recomienda reconocimiento inicial."

        critical = sum(1 for f in findings if f.get("severity") in {"critical", "Crítico"})
        return (
            f"Correlación heurística: {len(findings)} hallazgos, "
            f"{critical} críticos. Priorizar validación en servicios expuestos."
        )

    def propose_action(self, state: PentestGraphState) -> ProposedAction:
        executed = state.get("executed_tools", [])
        target = state.get("target", "unknown")

        if "nmap" not in executed:
            return {
                "tool": "nmap",
                "target": target,
                "rationale": "Fase de reconocimiento — identificar puertos y servicios",
                "params": {"port_range": "1-1024"},
            }
        if "nuclei" not in executed:
            return {
                "tool": "nuclei",
                "target": target,
                "rationale": "Fase de enumeración — detectar CVEs conocidos",
                "params": {},
            }
        return {
            "tool": "none",
            "target": target,
            "rationale": "No hay más herramientas pendientes en el flujo heurístico",
            "params": {},
        }

    def evaluate(self, state: PentestGraphState) -> EvaluationResult:
        proposed = state.get("proposed_action") or {}
        tool_result = state.get("tool_result")

        if proposed.get("tool") == "none":
            return {
                "sufficient": True,
                "continue_cycle": False,
                "reason": "Flujo heurístico completado — sin acciones pendientes",
            }

        if tool_result and not tool_result.get("success"):
            return {
                "sufficient": False,
                "continue_cycle": False,
                "reason": f"Fallo en herramienta {tool_result.get('tool')} — detener ciclo",
            }

        executed = state.get("executed_tools", [])
        if len(executed) >= 2:
            return {
                "sufficient": True,
                "continue_cycle": False,
                "reason": "Reconocimiento y escaneo de vulns completados",
            }

        if state.get("step_count", 0) >= state.get("max_steps", 5):
            return {
                "sufficient": False,
                "continue_cycle": False,
                "reason": "max_steps alcanzado — parada explícita",
            }

        return {
            "sufficient": False,
            "continue_cycle": True,
            "reason": "Información insuficiente — continuar ciclo de pentesting",
        }
