from langgraph.checkpoint.memory import MemorySaver

from atrox.ai.graph.decider import MockDecider
from atrox.ai.graph.graph import build_pentest_graph, get_persisted_state, run_pentest_orchestrator
from atrox.ai.graph.state import GraphPhase

SIMULATED_FINDINGS = [
    {
        "id": "VULN-001",
        "severity": "critical",
        "name": "SQL Injection",
        "vector": "POST /login.php",
    },
    {
        "id": "VULN-002",
        "severity": "high",
        "name": "Apache Path Traversal",
        "vector": "GET /cgi-bin/",
    },
]


def test_full_graph_traversal_with_simulated_data() -> None:
    result = run_pentest_orchestrator(
        findings=SIMULATED_FINDINGS,
        target="lab.target.local",
        thread_id="test-full-traversal",
        max_steps=5,
        decider=MockDecider(stop_after_cycles=1),
    )

    phases = [record["phase"] for record in result["history"]]

    assert GraphPhase.ANALYZE.value in phases
    assert GraphPhase.PROPOSE.value in phases
    assert GraphPhase.EXECUTE.value in phases
    assert GraphPhase.EVALUATE.value in phases

    assert result["analysis"] is not None
    assert result["proposed_action"] is not None
    assert result["tool_result"] is not None
    assert result["evaluation"] is not None

    assert result["should_stop"] is True
    assert result["stop_reason"] is not None
    assert len(result["executed_tools"]) >= 1


def test_state_persisted_between_transitions() -> None:
    memory = MemorySaver()
    thread_id = "test-persistence-001"

    result = run_pentest_orchestrator(
        findings=SIMULATED_FINDINGS,
        target="lab.target.local",
        thread_id=thread_id,
        max_steps=3,
        decider=MockDecider(stop_after_cycles=1),
        checkpointer=memory,
    )

    persisted = get_persisted_state(thread_id, checkpointer=memory)

    assert persisted is not None
    assert persisted["analysis"] == result["analysis"]
    assert persisted["stop_reason"] == result["stop_reason"]
    assert len(persisted["history"]) >= 4


def test_explicit_stop_on_max_steps() -> None:
    result = run_pentest_orchestrator(
        findings=SIMULATED_FINDINGS,
        target="lab.target.local",
        thread_id="test-max-steps",
        max_steps=1,
        decider=MockDecider(stop_after_cycles=99),
    )

    assert result["should_stop"] is True
    assert result["step_count"] <= 1 or result["stop_reason"] is not None


def test_cycle_repeats_until_stop_condition() -> None:
    result = run_pentest_orchestrator(
        findings=SIMULATED_FINDINGS,
        target="lab.target.local",
        thread_id="test-multi-cycle",
        max_steps=10,
        decider=MockDecider(stop_after_cycles=2),
    )

    analyze_count = sum(
        1 for h in result["history"] if h["phase"] == GraphPhase.ANALYZE.value
    )
    assert analyze_count >= 2
    assert result["should_stop"] is True


def test_simulated_tool_runner_integration() -> None:
    def custom_runner(tool: str, target: str, params: dict) -> dict:
        return {
            "success": True,
            "summary": f"Custom {tool} on {target}",
            "custom": True,
        }

    result = run_pentest_orchestrator(
        findings=SIMULATED_FINDINGS,
        target="custom.target.local",
        thread_id="test-custom-runner",
        decider=MockDecider(stop_after_cycles=1),
        tool_runner=custom_runner,
    )

    assert result["tool_result"] is not None
    assert result["tool_result"]["raw"].get("custom") is True


def test_graph_compiles_with_all_nodes() -> None:
    app = build_pentest_graph(decider=MockDecider())
    node_names = set(app.get_graph().nodes.keys())

    assert GraphPhase.ANALYZE.value in node_names
    assert GraphPhase.PROPOSE.value in node_names
    assert GraphPhase.EXECUTE.value in node_names
    assert GraphPhase.EVALUATE.value in node_names
