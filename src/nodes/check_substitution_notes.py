"""AgentCore Platform v1.0"""

# CheckSubstitutionNotes — verifies that mandatory substitution notes are present
# on BOM parts flagged by RoHS/REACH compliance check.
# Parts that are FAIL or WARN in rohs_reach_results_json require a non-empty
# substitution_note in the BOM line item.

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import from_json, to_json


class CheckSubstitutionNotesNode(FunctionNode):
    """Verify that mandatory substitution notes are present for RoHS/REACH-flagged parts.

    Reads parsed_bom_items_json and rohs_reach_results_json from state.
    Writes substitution_results_json (a JSON-encoded list) to state.

    A part is considered "flagged" if its rohs_reach status is FAIL or WARN.
    Flagged parts without a substitution_note in the BOM receive a FAIL verdict.
    Unflagged parts and flagged parts with a note both receive OK.
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
                "check_substitution_notes_error",
                {"reason": "no_bom_items"},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["CheckSubstitutionNotesNode: parsed_bom_items_json is empty"],
            }

        rohs_results = from_json(state.get("rohs_reach_results_json")) or []

        # Build set of part numbers that failed or warned on RoHS/REACH
        flagged_parts = {r["part_number"] for r in rohs_results if r.get("status") in ("FAIL", "WARN")}

        results = []
        fail_count = 0

        for item in items:
            pn = item.get("part_number", "").strip()
            note = item.get("substitution_note", "").strip()
            has_note = bool(note)

            if pn in flagged_parts:
                if has_note:
                    results.append(
                        {
                            "part_number": pn,
                            "has_substitution_note": True,
                            "status": "OK",
                            "message": "Mandatory substitution note is present",
                        }
                    )
                else:
                    fail_count += 1
                    results.append(
                        {
                            "part_number": pn,
                            "has_substitution_note": False,
                            "status": "FAIL",
                            "message": (
                                f"Part '{pn}' is flagged for RoHS/REACH but mandatory " "substitution note is missing"
                            ),
                        }
                    )
            else:
                results.append(
                    {
                        "part_number": pn,
                        "has_substitution_note": has_note,
                        "status": "OK",
                        "message": "",
                    }
                )

        emit_trace_event(
            "check_substitution_notes_complete",
            {
                "total": len(results),
                "flagged_parts": len(flagged_parts),
                "fail_count": fail_count,
            },
            state,
        )

        return {
            "substitution_results_json": to_json(results),
            "status": AgentStatus.SUCCESS.value,
        }
