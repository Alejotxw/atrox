"""Nodos del grafo de orquestación — analizar → proponer → ejecutar → evaluar (HU-013)."""

from typing import Callable

from atrox.ai.graph.decider import PentestDecider
from atrox.ai.graph.state import (
    GraphPhase,
    PentestGraphState,
    TransitionRecord,
)


def _append_history(state: PentestGraphState, phase: GraphPhase, summary: str) -> list[TransitionRecord]:
    history = list(state.get("history", []))
    history.append({"phase": phase.value, "summary": summary})
    return history


def make_analyze_node(decider: PentestDecider) -> Callable[[PentestGraphState], PentestGraphState]:
    def analyze_findings(state: PentestGraphState) -> PentestGraphState:
        analysis = decider.analyze_findings(state)
        return {
            **state,
            "analysis": analysis,
            "current_phase": GraphPhase.ANALYZE.value,
            "history": _append_history(state, GraphPhase.ANALYZE, analysis[:120]),
        }

    return analyze_findings


def make_propose_node(decider: PentestDecider) -> Callable[[PentestGraphState], PentestGraphState]:
    def propose_action(state: PentestGraphState) -> PentestGraphState:
        action = decider.propose_action(state)
        summary = f"{action['tool']} → {action['target']}: {action['rationale']}"
        return {
            **state,
            "proposed_action": action,
            "current_phase": GraphPhase.PROPOSE.value,
            "history": _append_history(state, GraphPhase.PROPOSE, summary[:120]),
        }

    return propose_action


def make_execute_node(
    tool_runner: Callable[[str, str, dict], dict] | None = None,
) -> Callable[[PentestGraphState], PentestGraphState]:
    def execute_tool(state: PentestGraphState) -> PentestGraphState:
        action = state.get("proposed_action") or {}
        tool = action.get("tool", "none")
        target = action.get("target", state.get("target", "unknown"))
        params = action.get("params", {})

        if tool == "none":
            result = {
                "tool": "none",
                "success": True,
                "output_summary": "Sin herramienta que ejecutar",
                "raw": {},
            }
        elif tool_runner is not None:
            raw = tool_runner(tool, target, params)
            result = {
                "tool": tool,
                "success": raw.get("success", True),
                "output_summary": raw.get("summary", f"{tool} ejecutado sobre {target}"),
                "raw": raw,
            }
        else:
            result = _simulate_tool(tool, target, params)

        executed = list(state.get("executed_tools", []))
        if tool != "none" and tool not in executed:
            executed.append(tool)

        summary = result["output_summary"]
        return {
            **state,
            "tool_result": result,
            "executed_tools": executed,
            "step_count": state.get("step_count", 0) + 1,
            "current_phase": GraphPhase.EXECUTE.value,
            "history": _append_history(state, GraphPhase.EXECUTE, summary[:120]),
        }

    return execute_tool


def make_evaluate_node(decider: PentestDecider) -> Callable[[PentestGraphState], PentestGraphState]:
    def evaluate(state: PentestGraphState) -> PentestGraphState:
        evaluation = decider.evaluate(state)
        should_stop = not evaluation["continue_cycle"]
        stop_reason = evaluation["reason"] if should_stop else None

        return {
            **state,
            "evaluation": evaluation,
            "should_stop": should_stop,
            "stop_reason": stop_reason,
            "current_phase": GraphPhase.STOPPED.value if should_stop else GraphPhase.EVALUATE.value,
            "history": _append_history(
                state,
                GraphPhase.EVALUATE,
                f"continue={evaluation['continue_cycle']} — {evaluation['reason']}"[:120],
            ),
        }

    return evaluate


def _simulate_tool(tool: str, target: str, params: dict) -> dict:
    """Simula ejecución de herramienta para laboratorio sin binarios externos."""
    if tool == "nmap":
        return {
            "tool": "nmap",
            "success": True,
            "output_summary": f"Nmap simulado: puertos 22,80,443 abiertos en {target}",
            "raw": {"ports": [22, 80, 443], "params": params},
        }
    if tool == "nuclei":
        return {
            "tool": "nuclei",
            "success": True,
            "output_summary": f"Nuclei simulado: 2 hallazgos críticos en {target}",
            "raw": {"findings_count": 2, "params": params},
        }
    return {
        "tool": tool,
        "success": False,
        "output_summary": f"Herramienta desconocida: {tool}",
        "raw": {},
    }
