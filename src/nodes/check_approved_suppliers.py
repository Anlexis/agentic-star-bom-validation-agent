"""AgentCore Platform v1.0"""

# CheckApprovedSuppliers — validates each BOM supplier against the configured
# Approved Supplier List (ASL).  When no ASL is configured, all suppliers pass.
# Config key: validation.approved_suppliers in config/config.yaml (a list of
# approved supplier names), read from state["agent_config_json"]

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import from_json, to_json


class CheckApprovedSuppliersNode(FunctionNode):
    """Validate BOM suppliers against the configurable Approved Supplier List (ASL).

    Reads parsed_bom_items_json from state.
    Writes supplier_results_json (a JSON-encoded list) to state.

    Config:
        approved_suppliers (list[str]): case-sensitive supplier names in the ASL.
            Declared under `validation` in config/config.yaml, checked and forwarded
            to the inner graph by BOMValidationGraphNode._parent_config() and
            republished into state as the JSON field agent_config_json.  If empty or
            absent, all suppliers are accepted (pass-through).
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> dict[str, Any]:
        # A reason settled earlier in the run is the real one: pass it through
        # untouched instead of doing work on input that was already declined.
        marker = state.get("error_code")
        if marker:
            return {"status": AgentStatus.SUCCESS.value, "error_code": marker}
        items = from_json(state.get("parsed_bom_items_json"))
        if not items:
            emit_trace_event(
                "check_approved_suppliers_error",
                {"reason": "no_bom_items"},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["CheckApprovedSuppliersNode: parsed_bom_items_json is empty"],
            }

        agent_config = from_json(state.get("agent_config_json")) or {}
        raw_asl = agent_config.get("approved_suppliers", [])
        approved = set(raw_asl) if raw_asl else set()

        results = []
        fail_count = 0
        for item in items:
            pn = item.get("part_number", "").strip()
            supplier = item.get("supplier", "").strip()

            if not approved or supplier in approved:
                results.append(
                    {
                        "part_number": pn,
                        "supplier": supplier,
                        "status": "OK",
                        "message": "",
                    }
                )
            else:
                fail_count += 1
                results.append(
                    {
                        "part_number": pn,
                        "supplier": supplier,
                        "status": "FAIL",
                        "message": (f"Supplier '{supplier}' for part '{pn}' is not in the Approved Supplier List"),
                    }
                )

        emit_trace_event(
            "check_approved_suppliers_complete",
            {
                "total": len(results),
                "fail_count": fail_count,
                "asl_size": len(approved) if approved else "unconfigured",
            },
            state,
        )

        return {
            "supplier_results_json": to_json(results),
            "status": AgentStatus.SUCCESS.value,
        }
