"""AgentCore Platform v1.0"""

# CheckRoHSREACH — validates RoHS (2011/65/EU) and REACH (EC No 1907/2006)
# compliance for each BOM part using the configured compliance table.
# Config key: validation.rohs_reach_db in config/config.yaml (a mapping of
# part_number → compliance record), read from state["agent_config_json"]

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import from_json, to_json


class CheckRoHSREACHNode(FunctionNode):
    """Check RoHS/REACH compliance for each BOM part.

    Reads parsed_bom_items_json from state.
    Writes rohs_reach_results_json (a JSON-encoded list) to state.

    Config:
        rohs_reach_db (dict): declared under `validation` in config/config.yaml,
            checked and forwarded to the inner graph by
            BOMValidationGraphNode._parent_config() and republished into state as
            the JSON field agent_config_json.
            Maps part_number to a compliance record:
            {
                "rohs_compliant": bool,         # True = passes RoHS
                "reach_compliant": bool,        # True = passes REACH SVHC check
                "hazardous_substances": list    # SVHC substance names (may be empty)
            }
        Parts absent from the database are assumed compliant (pass-through).
        This mirrors the JAMA/IMDS lookup model where absence = no known concern.
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
                "check_rohs_reach_error",
                {"reason": "no_bom_items"},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["CheckRoHSREACHNode: parsed_bom_items_json is empty"],
            }

        agent_config = from_json(state.get("agent_config_json")) or {}
        compliance_db = agent_config.get("rohs_reach_db", {})

        results = []
        fail_count = 0
        warn_count = 0

        for item in items:
            pn = item.get("part_number", "").strip()
            record = compliance_db.get(pn, {})

            rohs_ok = bool(record.get("rohs_compliant", True))
            reach_ok = bool(record.get("reach_compliant", True))
            substances = list(record.get("hazardous_substances", []))

            if rohs_ok and reach_ok:
                status = "OK"
                message = ""
            elif not rohs_ok and not reach_ok:
                fail_count += 1
                status = "FAIL"
                message = f"Part '{pn}' fails both RoHS (2011/65/EU) and REACH (EC 1907/2006) compliance"
            elif not rohs_ok:
                fail_count += 1
                status = "FAIL"
                message = f"Part '{pn}' fails RoHS (2011/65/EU) compliance"
            else:
                # REACH concern: hazardous substances present but still compliant
                warn_count += 1
                status = "WARN"
                substance_list = ", ".join(substances) if substances else "unspecified SVHC"
                message = f"Part '{pn}' has REACH SVHC concern: {substance_list}"

            results.append(
                {
                    "part_number": pn,
                    "rohs_compliant": rohs_ok,
                    "reach_compliant": reach_ok,
                    "hazardous_substances": substances,
                    "status": status,
                    "message": message,
                }
            )

        emit_trace_event(
            "check_rohs_reach_complete",
            {
                "total": len(results),
                "fail_count": fail_count,
                "warn_count": warn_count,
                "db_size": len(compliance_db),
            },
            state,
        )

        return {
            "rohs_reach_results_json": to_json(results),
            "status": AgentStatus.SUCCESS.value,
        }
