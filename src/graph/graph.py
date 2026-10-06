"""AgentCore Platform v1.0"""

# MFG-C2-012 — Manufacturing BOM Validation Agent
# Outer graph (AgentBaseGraph; Cat 2 two-layer nested architecture)
#
# Architecture (Cat 2):
#
#   Outer backbone (fixed — never override add_edges()):
#     START -> initialize -> pre_process -> main -> {route} -> post_process -> finalize -> END
#                                               ↓ (RETRY, bounded by max_retry)
#                                            pre_process
#
#   The `main` slot is BOMValidationGraphNode (GraphNode subclass) that
#   delegates the full domain workflow to BOMValidationWorkflowGraph (inner BaseGraph).
#
#   Domain complexity is fully encapsulated inside the inner graph.  The outer
#   backbone is never modified.
#
# Directory layout:
#   src/graph/graph.py                 <- outer graph (this file)
#   src/graph/domain_workflow_graph.py <- inner graph (multi-step BOM validation)
#   src/graph/context_bridge.py        <- caller input_context hand-off across the boundary
#
# Class-name alignment (must match across all three):
#   graph.py class   : ManufacturingBOMValidationAgent
#   config/agent.yaml: class: "src.graph.graph.ManufacturingBOMValidationAgent"
#   src/api/server.py: from src.graph.graph import ManufacturingBOMValidationAgent
#
# Rules enforced:
#   - ManufacturingBOMValidationAgent inherits AgentBaseGraph (framework base class)
#   - super().register_nodes() called first (fills initialize + finalize)
#   - BOMValidationGraphNode assigned to self._nodes["main"]
#   - merge_output() returns only changed keys
#   - add_edges() NOT overridden on the outer graph

import math
import re
from pathlib import Path
from typing import Any, ClassVar, Optional

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.nodes.graph_node import GraphNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from src.graph.context_bridge import set_caller_input_context
from src.nodes.security_gate_output import SecurityGateOutputNode
from src.nodes.validate_input import ValidateInputNode
from src.schemas.state import State

# Runtime config path: src/graph/graph.py -> parents[2] = repo root.
_RUNTIME_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"

# Bounds applied to declared (operator-supplied) validation rules before they
# are forwarded to the domain nodes.
_MAX_PATTERN_CHARS = 200
_MAX_ASL_ENTRIES = 10_000
_MAX_SUPPLIER_NAME_CHARS = 128
_MAX_COMPLIANCE_ENTRIES = 100_000
_LINE_ITEM_CEILING = 50_000

# Operation descriptor handed to the inner graph as user_input. The BOM record
# itself travels on the context channel (see src/graph/context_bridge.py), so
# no caller document text is placed in this field.
_INNER_OPERATION = "validate_bom"


def _runtime_config() -> dict[str, Any]:
    """Read the runtime parameters from config/config.yaml.

    This is the same file the platform registry loads and passes as
    Graph(config=...); the standalone server (src/api/server.py) reads it here
    so a registry-loaded agent and the deployed standalone agent see identical
    configuration. Returns an empty dict — never raises — when the file is
    absent, unreadable, not valid YAML, or not a mapping; the graph then runs
    on its built-in defaults.
    """
    try:
        import yaml

        loaded = yaml.safe_load(_RUNTIME_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(loaded, dict):
        return {}
    return loaded


def _config_int(value: Any, lo: int, hi: int) -> Optional[int]:
    """Validate a declared integer setting: a real integer, finite, within [lo, hi].

    Bools are rejected explicitly (``isinstance(True, int)`` is True in Python,
    so ``max_line_items: true`` would otherwise pass as 1). Floats are accepted
    only when finite and integral — a NaN or Infinity here would compare False
    against every bound and silently disable the ceiling it exists to impose.
    Anything else returns None and the node keeps its built-in default.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, float):
        if not math.isfinite(value) or value != int(value):
            return None
        parsed = int(value)
    else:
        return None
    return parsed if lo <= parsed <= hi else None


def _validated_rules(cfg: dict[str, Any]) -> dict[str, Any]:
    """Extract and validate the `validation` block from the runtime configuration.

    Every rule is checked here rather than inside the domain nodes so a
    malformed configuration file can neither crash graph construction nor
    change a verdict in a way the operator did not declare:

    * ``part_number_pattern`` must be a bounded, compilable regular expression —
      an uncompilable pattern would otherwise fail every part number in the BOM.
    * ``approved_suppliers`` must be a bounded list of bounded strings — a
      non-list would make the membership test behave as "no ASL configured",
      i.e. pass every supplier.
    * ``rohs_reach_db`` must be a bounded mapping of part number to record.
    * ``max_line_items`` must be a finite integer inside the hard ceiling.

    Invalid or absent keys are simply not forwarded; each node then falls back
    to its documented default.
    """
    raw = cfg.get("validation")
    block: dict[str, Any] = raw if isinstance(raw, dict) else {}
    rules: dict[str, Any] = {}

    pattern = block.get("part_number_pattern")
    if isinstance(pattern, str) and 0 < len(pattern) <= _MAX_PATTERN_CHARS:
        try:
            re.compile(pattern)
        except re.error:
            pass
        else:
            rules["part_number_pattern"] = pattern

    suppliers = block.get("approved_suppliers")
    if isinstance(suppliers, list) and len(suppliers) <= _MAX_ASL_ENTRIES:
        names = [s for s in suppliers if isinstance(s, str) and 0 < len(s) <= _MAX_SUPPLIER_NAME_CHARS]
        if len(names) == len(suppliers):
            rules["approved_suppliers"] = names

    compliance = block.get("rohs_reach_db")
    if isinstance(compliance, dict) and len(compliance) <= _MAX_COMPLIANCE_ENTRIES:
        records = {k: v for k, v in compliance.items() if isinstance(k, str) and isinstance(v, dict)}
        if len(records) == len(compliance):
            rules["rohs_reach_db"] = records

    ceiling = _config_int(block.get("max_line_items"), 1, _LINE_ITEM_CEILING)
    if ceiling is not None:
        rules["max_line_items"] = ceiling

    return rules


class BOMValidationGraphNode(GraphNode):
    """GraphNode subclass assigned to the `main` slot of the outer graph.

    Wraps BOMValidationWorkflowGraph (inner Cat 2 BaseGraph).
    Called by the AgentBaseGraph backbone after pre_process and before post_process.

    Contracts:
      _parent_config() — validate the declared domain rules and forward them to
                         the inner graph under config["configurable"]
      get_subgraph()   — instantiate BOMValidationWorkflowGraph with that config
      extract_input()  — stash the validated BOM record on the context channel
                         and hand the inner graph an operation descriptor
      merge_output()   — map sub_result fields into the outer state delta
                         (changed keys only)
      error_strategy   — "propagate": re-raise inner errors as SubgraphError (fail-fast)
    """

    error_strategy: ClassVar[str] = "propagate"
    propagate_hitl: ClassVar[bool] = False

    def _parent_config(self) -> dict[str, Any]:
        """Forward the validated domain rules to the inner graph.

        Reads config/config.yaml (see _runtime_config) and returns the checked
        `validation` block under config["configurable"]. Without this
        forwarding every declared rule is dead: the inner graph is constructed
        with an empty config, so the domain nodes never see a declared value
        and always fall back to their built-in defaults.

        BOMValidationWorkflowGraph._extra_initial_state() republishes this
        block into the inner graph's initial state as the JSON string field
        `agent_config_json`, which is where ValidatePartNumbersNode,
        CheckApprovedSuppliersNode and CheckRoHSREACHNode read their rules.

        Degrades to an empty `configurable` block — never raises — when the
        file is missing, unreadable, not valid YAML, or carries no usable
        `validation` mapping. A malformed configuration must not take the agent
        down; the nodes then use their documented defaults.
        """
        return {"configurable": _validated_rules(_runtime_config())}

    def get_subgraph(self) -> Any:
        """Instantiate and return the inner BOMValidationWorkflowGraph.

        Lazy import avoids circular-import risk at module load time.
        The inner graph receives the validated rules through the BaseGraph
        constructor; its domain NODES still take no constructor arguments and
        read their configuration from state.
        """
        from src.graph.domain_workflow_graph import BOMValidationWorkflowGraph

        return BOMValidationWorkflowGraph(config=self._parent_config())

    def execute(self, state: AgentState) -> dict[str, Any]:
        """Skip the inner graph when the request was already found unacceptable.

        A request declined by pre_process has no validated input to act on, so
        running the inner graph would only produce a second, vaguer reason for
        the same rejection - and overwrite the specific one already settled.
        """
        marker = state.get("error_code")
        if marker:
            return {"status": AgentStatus.SUCCESS.value, "error_code": marker}
        result: dict[str, Any] = super().execute(state)
        return result

    def extract_input(self, state: AgentState) -> str:
        """Hand the BOM record to the inner graph over the context channel.

        The framework invokes the inner graph with user_input only, so the
        validated BOM record is stashed in a ContextVar here (this method runs
        immediately before ``subgraph.invoke``) and re-seeded into the inner
        initial state by BOMValidationWorkflowGraph._extra_initial_state().

        The returned user_input is a fixed operation descriptor and carries no
        caller document text: routing the BOM through user_input would expose
        it to the framework's personal-name masking, which rewrites two-word
        supplier and component labels and would make the report — and the
        Approved-Supplier-List comparison — run against masked names.
        """
        set_caller_input_context(
            {
                "bom_content": state.get("bom_content") or "",
                "bom_format": state.get("bom_format") or "csv",
                "max_line_items": state.get("max_line_items"),
            }
        )
        return _INNER_OPERATION

    def merge_output(self, state: AgentState, sub_result: dict[str, Any]) -> dict[str, Any]:
        """Map the inner graph sub_result back into the outer state delta.

        sub_result is the dict returned by BOMValidationWorkflowGraph.get_output().
        Returns ONLY changed keys — never the full state.

        Key coupling (designed together with BOMValidationWorkflowGraph.get_output()):
            inner get_output()  emits: "output" (report text), "report" (structured
                                report), "status"
            this merge_output() reads: sub_result["output"], sub_result["report"],
                                sub_result["status"]

        The structured report is carried across as well as the text: the output
        boundary in SecurityGateOutputNode screens BOTH representations, and a
        representation the gate cannot see is a representation it cannot
        protect.
        """
        return {
            # Outer reason wins: a reason settled before the inner run is the real
            # one, and a plain sub_result.get() would erase it.
            "error_code": state.get("error_code") or sub_result.get("error_code", ""),
            "result": sub_result.get("output"),
            "validation_report_json": sub_result.get("report"),
            "status": sub_result.get("status"),
        }


class ManufacturingBOMValidationAgent(AgentBaseGraph):
    """Outer graph for the MFG-C2-012 Manufacturing BOM Validation Agent (Cat 2).

    Inherits AgentBaseGraph directly (framework base class). Domain logic is
    fully encapsulated in BOMValidationGraphNode (main slot), which delegates
    to BOMValidationWorkflowGraph (inner BaseGraph).

    Backbone (fixed):
        START -> initialize -> pre_process -> main -> post_process -> finalize -> END

    register_nodes() is the ONLY override:
      - super().register_nodes() fills: initialize, finalize (framework defaults)
      - pre_process:  ValidateInputNode      (caller-data contract; VERIFIED_EXTERNAL)
      - main:         BOMValidationGraphNode (delegates to BOMValidationWorkflowGraph)
      - post_process: SecurityGateOutputNode (external output boundary; ANONYMOUS)

    add_edges() is NOT overridden — backbone wiring belongs to the framework.
    """

    @property
    def name(self) -> str:
        """Agent identifier registered with AgentRegistry."""
        return "ManufacturingBOMValidationAgent"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        """Fill all 5 backbone slots.

        super().register_nodes() MUST be called first — it injects the
        framework's default InitializeNode (sets schema_version, session_id,
        trust_level) and FinalizeNode (builds response_metadata, total_time_ms).
        """
        super().register_nodes()  # fills: initialize, finalize

        self._nodes["pre_process"] = ValidateInputNode()
        self._nodes["main"] = BOMValidationGraphNode()
        self._nodes["post_process"] = SecurityGateOutputNode()

    # add_edges() is NOT overridden — backbone wiring belongs to the framework.

    def get_output(self, state: AgentState) -> dict[str, Any]:
        """Resolve the caller-facing envelope, refusing to fall back on a failure.

        AgentBaseGraph.get_output() is `formatted_output or result` with no
        status check, so on any non-success it hands back whatever `result`
        still holds. SecurityGateOutputNode clears `result` on the refusals it
        owns, but it cannot clear anything on the paths where its delta never
        lands: when the framework's @final output-safety hook raises,
        BaseNode.__call__ discards the node's whole return value and emits a
        bare ERROR partial that sets only status / error_log / node_history /
        execution_time. The pre_process rejection and the trust-gate denial
        branch have the same shape.

        So the fallback is re-resolved here rather than trusted: on a
        non-success the envelope carries the gate's own notice when it exists,
        and otherwise nothing. `formatted_output or None` and not
        `state.get("formatted_output")` on purpose — an empty-string notice is
        falsy, and passing it through unchanged would be indistinguishable from
        withholding while meaning the opposite everywhere else it is read.

        This is the second half of the containment fix and is falsifiable on its
        own: revert it and the bare-ERROR case in
        tests/unit/test_output_boundary.py surfaces the report again.
        """
        output: dict[str, Any] = super().get_output(state)
        if state.get("status") != AgentStatus.SUCCESS.value:
            output["output"] = state.get("formatted_output") or None
        return output
