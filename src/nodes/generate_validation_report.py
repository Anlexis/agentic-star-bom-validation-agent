"""AgentCore Platform v1.0"""

# GenerateValidationReport — compiles per-line-item validation results from all
# preceding domain nodes into a structured report and a human-readable text summary.

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import from_json, to_json


def _worst_status(statuses: list[str]) -> str:
    """Return the worst status across a list of per-check status strings."""
    if "FAIL" in statuses:
        return "FAIL"
    if "WARN" in statuses:
        return "WARN"
    return "OK"


class GenerateValidationReportNode(FunctionNode):
    """Compile all domain-node results into a structured BOM validation report.

    Reads:
        parsed_bom_items_json, part_number_results_json, supplier_results_json,
        rohs_reach_results_json, substitution_results_json

    Writes:
        validation_report_json  (JSON-encoded structured report)
        result                  (human-readable text report for post_process)

    Both representations carry the same per-line findings and both cross the
    external boundary, so both are screened by SecurityGateOutputNode.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> dict[str, Any]:
        # A reason settled earlier in the run is the real one: pass it through
        # untouched instead of doing work on input that was already declined.
        marker = state.get("error_code")
        if marker:
            return {"status": AgentStatus.SUCCESS.value, "error_code": marker}
        items = from_json(state.get("parsed_bom_items_json")) or []
        pn_results = from_json(state.get("part_number_results_json")) or []
        supplier_results = from_json(state.get("supplier_results_json")) or []
        rohs_results = from_json(state.get("rohs_reach_results_json")) or []
        sub_results = from_json(state.get("substitution_results_json")) or []

        # Build lookup maps keyed by part_number
        pn_map = {r["part_number"]: r for r in pn_results}
        sup_map = {r["part_number"]: r for r in supplier_results}
        rohs_map = {r["part_number"]: r for r in rohs_results}
        sub_map = {r["part_number"]: r for r in sub_results}

        line_items = []
        total_ok = total_warn = total_fail = 0

        for item in items:
            pn = item.get("part_number", "")

            per_check_statuses = [
                pn_map.get(pn, {}).get("status", "OK"),
                sup_map.get(pn, {}).get("status", "OK"),
                rohs_map.get(pn, {}).get("status", "OK"),
                sub_map.get(pn, {}).get("status", "OK"),
            ]
            line_status = _worst_status(per_check_statuses)

            if line_status == "FAIL":
                total_fail += 1
            elif line_status == "WARN":
                total_warn += 1
            else:
                total_ok += 1

            # Collect non-empty finding messages
            findings = [
                r.get("message", "")
                for r in [
                    pn_map.get(pn, {}),
                    sup_map.get(pn, {}),
                    rohs_map.get(pn, {}),
                    sub_map.get(pn, {}),
                ]
                if r.get("message")
            ]

            line_items.append(
                {
                    "part_number": pn,
                    "supplier": item.get("supplier", ""),
                    "quantity": item.get("quantity"),
                    "status": line_status,
                    "findings": findings,
                }
            )

        total_items = len(items)
        passed = total_fail == 0

        report = {
            "summary": {
                "total_items": total_items,
                "ok_count": total_ok,
                "warn_count": total_warn,
                "fail_count": total_fail,
                "passed": passed,
            },
            "line_items": line_items,
        }

        # ── Human-readable text report ────────────────────────────────────────
        overall = "PASS" if passed else "FAIL"
        text_lines = [
            "=== BOM Validation Report ===",
            f"Overall: {overall}",
            f"Total: {total_items} items | OK: {total_ok} | WARN: {total_warn} | FAIL: {total_fail}",
            "",
        ]
        for li in line_items:
            prefix = f"[{li['status']}]"
            quantity = li["quantity"]
            rendered_quantity = str(quantity) if quantity is not None else "-"
            text_lines.append(f"{prefix} {li['part_number']} | {li['supplier']} | qty: {rendered_quantity}")
            for finding in li.get("findings", []):
                text_lines.append(f"       -> {finding}")

        report_text = "\n".join(text_lines)

        emit_trace_event(
            "generate_validation_report_complete",
            {
                "total_items": total_items,
                "ok_count": total_ok,
                "warn_count": total_warn,
                "fail_count": total_fail,
                "passed": passed,
            },
            state,
        )

        return {
            "validation_report_json": to_json(report),
            "result": report_text,
            "status": AgentStatus.SUCCESS.value,
        }
