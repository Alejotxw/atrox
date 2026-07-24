"""Construcción y ejecución del grafo LangGraph de orquestación (HU-013)."""

from typing import Any, Callable
from uuid import uuid4

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from atrox.ai.graph.decider import HeuristicDecider, MockDecider, PentestDecider
from atrox.ai.graph.nodes import (
    make_analyze_node,
    make_evaluate_node,
    make_execute_node,
    make_propose_node,
)
from atrox.ai.graph.state import GraphPhase, PentestGraphState


def _route_after_evaluate(state: PentestGraphState) -> str:
    """Condición de parada explícita o continuación del ciclo."""
    if state.get("should_stop"):
        return "stop"
    if state.get("step_count", 0) >= state.get("max_steps", 5):
        return "stop"
    return "continue"


def build_pentest_graph(
    decider: PentestDecider | None = None,
    tool_runner: Callable[[str, str, dict], dict] | None = None,
    checkpointer: MemorySaver | None = None,
):
    """Compila el grafo: analizar → proponer → ejecutar → evaluar (cíclico)."""
    decision_engine = decider or HeuristicDecider()

    graph = StateGraph(PentestGraphState)

    graph.add_node(GraphPhase.ANALYZE.value, make_analyze_node(decision_engine))
    graph.add_node(GraphPhase.PROPOSE.value, make_propose_node(decision_engine))
    graph.add_node(GraphPhase.EXECUTE.value, make_execute_node(tool_runner))
    graph.add_node(GraphPhase.EVALUATE.value, make_evaluate_node(decision_engine))

    graph.add_edge(START, GraphPhase.ANALYZE.value)
    graph.add_edge(GraphPhase.ANALYZE.value, GraphPhase.PROPOSE.value)
    graph.add_edge(GraphPhase.PROPOSE.value, GraphPhase.EXECUTE.value)
    graph.add_edge(GraphPhase.EXECUTE.value, GraphPhase.EVALUATE.value)
    graph.add_conditional_edges(
        GraphPhase.EVALUATE.value,
        _route_after_evaluate,
        {
            "continue": GraphPhase.ANALYZE.value,
            "stop": END,
        },
    )

    memory = checkpointer or MemorySaver()
    return graph.compile(checkpointer=memory)


def run_pentest_orchestrator(
    findings: list[dict[str, Any]],
    target: str,
    *,
    thread_id: str | None = None,
    max_steps: int = 5,
    decider: PentestDecider | None = None,
    tool_runner: Callable[[str, str, dict], dict] | None = None,
    checkpointer: MemorySaver | None = None,
) -> PentestGraphState:
    """
    Ejecuta el grafo completo con estado persistido entre transiciones.
    Retorna el estado final tras alcanzar la condición de parada.
    """
    memory = checkpointer or MemorySaver()
    app = build_pentest_graph(decider=decider, tool_runner=tool_runner, checkpointer=memory)

    session_id = thread_id or str(uuid4())
    config = {"configurable": {"thread_id": session_id}}

    initial_state: PentestGraphState = {
        "findings": findings,
        "target": target,
        "analysis": None,
        "proposed_action": None,
        "tool_result": None,
        "evaluation": None,
        "current_phase": GraphPhase.INIT.value,
        "step_count": 0,
        "max_steps": max_steps,
        "should_stop": False,
        "stop_reason": None,
        "history": [],
        "executed_tools": [],
    }

    final_state = app.invoke(initial_state, config=config)
    return final_state


def get_persisted_state(
    thread_id: str,
    checkpointer: MemorySaver | None = None,
) -> PentestGraphState | None:
    """Recupera el último estado persistido de una sesión."""
    memory = checkpointer or MemorySaver()
    app = build_pentest_graph(checkpointer=memory)
    config = {"configurable": {"thread_id": thread_id}}
    snapshot = app.get_state(config)
    if snapshot.values:
        return snapshot.values  # type: ignore[return-value]
    return None
