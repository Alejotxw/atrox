"""Estado compartido del grafo de orquestación de pentesting (HU-013)."""

from enum import Enum
from typing import Any, TypedDict


class GraphPhase(str, Enum):
    INIT = "init"
    ANALYZE = "analyze_findings"
    PROPOSE = "propose_action"
    EXECUTE = "execute_tool"
    EVALUATE = "evaluate"
    STOPPED = "stopped"


class ProposedAction(TypedDict):
    tool: str
    target: str
    rationale: str
    params: dict[str, Any]


class ToolExecutionResult(TypedDict):
    tool: str
    success: bool
    output_summary: str
    raw: dict[str, Any]


class EvaluationResult(TypedDict):
    sufficient: bool
    continue_cycle: bool
    reason: str


class TransitionRecord(TypedDict):
    phase: str
    summary: str


class PentestGraphState(TypedDict, total=False):
    """Estado persistido entre transiciones del grafo."""

    findings: list[dict[str, Any]]
    target: str
    analysis: str | None
    proposed_action: ProposedAction | None
    tool_result: ToolExecutionResult | None
    evaluation: EvaluationResult | None
    current_phase: str
    step_count: int
    max_steps: int
    should_stop: bool
    stop_reason: str | None
    history: list[TransitionRecord]
    executed_tools: list[str]
