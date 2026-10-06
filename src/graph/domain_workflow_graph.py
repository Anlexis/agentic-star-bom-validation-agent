"""AgentCore Platform v1.0"""

# BOMValidationWorkflowGraph — inner Cat-2 domain graph for MFG-C2-012
# Orchestrates the multi-step BOM validation pipeline:
#   parse → validate part numbers → check suppliers → check RoHS/REACH
#   → check substitution notes → generate report
#
# Called by BOMValidationGraphNode.get_subgraph() in src/graph/graph.py.
# Inherits BaseGraph (fully custom node topology with no backbone slots).

from typing import Any

from langgraph.graph import END, START

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from src.graph.context_bridge import get_caller_input_context
from src.nodes.parse_bom_file import ParseBOMFileNode
from src.nodes.validate_part_numbers import ValidatePartNumbersNode
from src.nodes.check_approved_suppliers import CheckApprovedSuppliersNode
from src.nodes.check_rohs_reach import CheckRoHSREACHNode
from src.nodes.check_substitution_notes import CheckSubstitutionNotesNode
from src.nodes.generate_validation_report import GenerateValidationReportNode
from src.schemas.state import State, to_json


class BOMValidationWorkflowGraph(BaseGraph):
    """Inner domain workflow graph for MFG-C2-012 Manufacturing BOM Validation Agent.

    Implements all 7 BaseGraph abstract methods.
    Node pipeline (linear):
        START
          -> parse_bom_file
          -> validate_part_numbers
          -> check_approved_suppliers
          -> check_rohs_reach
          -> check_substitution_notes
          -> generate_validation_report
          -> END

    All domain nodes are instantiated with NO constructor arguments (SDK-v1 contract).
    Manifest config is forwarded by BOMValidationGraphNode._parent_config() into
    this graph's constructor and republished into the inner initial state by
    _extra_initial_state(); nodes read it from state, keeping every execute()
    signature at execute(self, state) -> dict.
    initialize / finalize are outer backbone concerns — not registered here.
    """

    # ── Identity ──────────────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "bom_validation_workflow"

    @property
    def state_schema(self) -> type:
        return State

    # ── Config validation ─────────────────────────────────────────────────────

    def _validate_config(self) -> None:
        """No mandatory config keys — all domain config is optional with defaults."""
        pass

    # ── Config forwarding into state (manifest -> inner nodes) ────────────────

    def _extra_initial_state(self) -> dict[str, Any]:
        """Seed the inner initial state with the forwarded rules and caller record.

        Two hand-offs land here, both of which the framework does not perform
        for a nested graph:

        1. BOMValidationGraphNode._parent_config() forwards the validated
           `validation` block under config["configurable"]. This hook makes it
           reachable by the domain nodes at runtime as the JSON-string state
           field `agent_config_json` (state stores dict/list values as JSON
           strings, never bare objects), which ValidatePartNumbersNode,
           CheckApprovedSuppliersNode and CheckRoHSREACHNode read with
           from_json(). Passing configuration through state rather than a
           second execute() argument is what keeps every node at the canonical
           execute(self, state) -> dict.

        2. The caller's BOM record, stashed by
           BOMValidationGraphNode.extract_input() immediately before this
           invocation (src/graph/context_bridge.py). GraphNode.execute() calls
           subgraph.invoke(user_input, ...) without forwarding input_context,
           so without this line ParseBOMFileNode would see an empty context.
        """
        configurable = (self.config or {}).get("configurable") or {}
        return {
            "agent_config_json": to_json(configurable),
            "input_context": get_caller_input_context(),
        }

    # ── Node registration ─────────────────────────────────────────────────────

    def register_nodes(self) -> None:
        """Register all domain nodes with NO constructor arguments (SDK-v1 contract).

        No super() call — BaseGraph.register_nodes() is abstract.
        Do NOT register initialize or finalize (outer backbone concern).
        Every key registered here is referenced in add_edges().
        """
        self._nodes["parse_bom_file"] = ParseBOMFileNode()
        self._nodes["validate_part_numbers"] = ValidatePartNumbersNode()
        self._nodes["check_approved_suppliers"] = CheckApprovedSuppliersNode()
        self._nodes["check_rohs_reach"] = CheckRoHSREACHNode()
        self._nodes["check_substitution_notes"] = CheckSubstitutionNotesNode()
        self._nodes["generate_validation_report"] = GenerateValidationReportNode()

    # ── Edge wiring ───────────────────────────────────────────────────────────

    def add_edges(self) -> None:
        """Wire the linear BOM validation pipeline.

        All six domain nodes are reachable from START; the last exits to END.
        No conditional branching — linear topology throughout.
        """
        self._sg.add_edge(START, "parse_bom_file")
        self._sg.add_edge("parse_bom_file", "validate_part_numbers")
        self._sg.add_edge("validate_part_numbers", "check_approved_suppliers")
        self._sg.add_edge("check_approved_suppliers", "check_rohs_reach")
        self._sg.add_edge("check_rohs_reach", "check_substitution_notes")
        self._sg.add_edge("check_substitution_notes", "generate_validation_report")
        self._sg.add_edge("generate_validation_report", END)

    # ── Routing ───────────────────────────────────────────────────────────────

    def route(self, state: AgentState) -> str:
        """Required by BaseGraph ABC.

        Linear topology — add_conditional_edges() is not used, so this method
        is never called at runtime.  Returns END on error to satisfy the contract.
        """
        if state.get("status") == AgentStatus.ERROR.value:
            return END
        return "generate_validation_report"

    # ── Output shape ──────────────────────────────────────────────────────────

    def get_output(self, state: AgentState) -> dict[str, Any]:
        """Shape the sub_result dict returned to BOMValidationGraphNode.merge_output().

        Designed together with merge_output() in src/graph/graph.py:
            sub_result   = self.get_output(final_inner_state)   # here
            outer_delta  = outer_node.merge_output(outer_state, sub_result)  # in graph.py

        The "output" key carries the human-readable validation report text and
        "report" the structured JSON report — the output boundary screens both
        representations, so both must cross the boundary.

        Both are surfaced ONLY on the success path. An unconditional
        `output["result"] = state.get("result")` here is the second half of the
        envelope-containment defect: a report the inner pipeline refused to
        stand behind would cross into the outer state through
        merge_output() and become the outer `result`, which
        AgentBaseGraph.get_output() falls back to whenever formatted_output is
        falsy.

        BOMValidationGraphNode sets error_strategy = "propagate", so today an
        inner ERROR raises SubgraphError before merge_output() is ever called
        and this branch is not reachable through /invoke. It is asserted
        directly instead (tests/unit/test_output_boundary.py) rather than left
        as the one thing standing between a strategy change and a leak.
        """
        if state.get("status") != AgentStatus.SUCCESS.value:
            return {
                # the reason must leave the subgraph or the outer graph cannot report it
                "error_code": state.get("error_code"),
                "output": None,
                "report": None,
                "status": state.get("status"),
                "trace_id": state.get("trace_id"),
                "correlation_id": state.get("correlation_id"),
                "node_history": state.get("node_history", []),
            }
        return {
            # A rejection the caller can correct completes with SUCCESS and carries
            # a reason code, so it lands here rather than in the branch above. The
            # code has to cross the boundary on this path too: merge_output() reads
            # it to decide whether a report was produced at all, and without it the
            # caller receives an empty answer with no reason.
            "error_code": state.get("error_code", ""),
            "output": state.get("result"),
            "report": state.get("validation_report_json"),
            "status": state.get("status"),
            "trace_id": state.get("trace_id"),
            "correlation_id": state.get("correlation_id"),
            "node_history": state.get("node_history", []),
        }
