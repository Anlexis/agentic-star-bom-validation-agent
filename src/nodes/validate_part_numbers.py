"""AgentCore Platform v1.0"""

# ValidatePartNumbers — validates each BOM line item part number against the
# configured OEM format rule.
# Config key: validation.part_number_pattern in config/config.yaml, forwarded to
# the inner graph and read from state["agent_config_json"]
# (default: OEM-style alphanumeric)

import re
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import from_json, to_json

# Default OEM part-number format: 2–4 uppercase letters, dash, 4–8 digits,
# optional dash + 1–4 uppercase alphanumeric suffix
# Example valid: AB-12345, ABCD-12345678, AB-1234-R1
_DEFAULT_PART_NUMBER_PATTERN = r"^[A-Z]{2,4}-\d{4,8}(-[A-Z0-9]{1,4})?$"


class ValidatePartNumbersNode(FunctionNode):
    """Validate BOM part numbers against OEM format rules.

    Reads parsed_bom_items_json from state.
    Writes part_number_results_json (a JSON-encoded list) to state.

    Config:
        part_number_pattern (str): regex for valid part numbers. Declared under
            `validation` in config/config.yaml, checked and forwarded to the inner
            graph by BOMValidationGraphNode._parent_config(), and republished into
            state as the JSON field agent_config_json. Defaults to the standard
            OEM alphanumeric format when absent.
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
                "validate_part_numbers_error",
                {"reason": "no_bom_items"},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["ValidatePartNumbersNode: parsed_bom_items_json is empty"],
            }

        agent_config = from_json(state.get("agent_config_json")) or {}
        pattern = agent_config.get("part_number_pattern", _DEFAULT_PART_NUMBER_PATTERN)

        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            emit_trace_event(
                "validate_part_numbers_error",
                {"reason": "invalid_pattern", "detail": str(exc)},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": [f"ValidatePartNumbersNode: invalid part_number_pattern — {exc}"],
            }

        results = []
        fail_count = 0
        for item in items:
            pn = item.get("part_number", "").strip()
            if compiled.match(pn):
                results.append({"part_number": pn, "status": "OK", "message": ""})
            else:
                fail_count += 1
                results.append(
                    {
                        "part_number": pn,
                        "status": "FAIL",
                        "message": f"Part number '{pn}' does not match OEM format rule",
                    }
                )

        emit_trace_event(
            "validate_part_numbers_complete",
            {"total": len(results), "fail_count": fail_count},
            state,
        )

        return {
            "part_number_results_json": to_json(results),
            "status": AgentStatus.SUCCESS.value,
        }
