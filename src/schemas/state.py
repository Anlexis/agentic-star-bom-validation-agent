"""AgentCore Platform v1.0"""

# State is a flat TypedDict — never a Pydantic model. Checkpoints are
# msgpack-serialized, and rich Python objects corrupt silently on the way
# back. All dict/list fields are stored as Optional[str] (JSON-encoded) and
# accessed via the to_json / from_json helpers below.

import json
from typing import Any, Optional

from framework.schemas.agent_state import AgentState


def to_json(obj: Any) -> Optional[str]:
    """Serialize a dict or list to a JSON string. Returns None if obj is None."""
    if obj is None:
        return None
    return json.dumps(obj, ensure_ascii=False)


def from_json(s: Optional[str]) -> Any:
    """Deserialize a JSON string to a Python dict or list. Returns None if s is None."""
    if not s:
        return None
    return json.loads(s)


class State(AgentState):
    """MFG-C2-012 Manufacturing BOM Validation Agent state.

    Checkpoint-safety rules:
    - All list/dict fields stored as Optional[str] (JSON-encoded).
    - Use to_json() when writing, from_json() when reading list/dict fields.
    - No Pydantic models, dataclasses, or arbitrary Python objects.
    - No credentials or secrets — those flow via InvocationContext/secrets_factory only.
    """

    # ── Manifest runtime configuration (forwarded into the inner graph) ───────
    # JSON-encoded copy of the validated `validation` block from
    # config/config.yaml, published into the inner graph's initial state by
    # BOMValidationWorkflowGraph._extra_initial_state().  Domain nodes read it
    # with from_json() instead of taking a second execute() parameter, which
    # keeps the node contract at execute(self, state) -> dict.
    agent_config_json: Optional[str]

    # ── ValidateInput output ──────────────────────────────────────────────────
    validated_input: Optional[str]  # sanitised user_input string

    # ── BOM record accepted from the caller ───────────────────────────────────
    bom_content: Optional[str]  # raw BOM file content (CSV or XML text)
    bom_format: Optional[str]  # "csv" | "xml"
    max_line_items: Optional[int]  # caller ceiling on processed line items

    # ── ParseBOMFile output (JSON-encoded list) ──────────────────────────────
    # JSON: list of {part_number, supplier, quantity, spec_ref, substitution_note}
    parsed_bom_items_json: Optional[str]

    # ── ValidatePartNumbers output (JSON-encoded list) ───────────────────────
    # JSON: list of {part_number, status: OK|FAIL, message}
    part_number_results_json: Optional[str]

    # ── CheckApprovedSuppliers output (JSON-encoded list) ────────────────────
    # JSON: list of {part_number, supplier, status: OK|FAIL, message}
    supplier_results_json: Optional[str]

    # ── CheckRoHSREACH output (JSON-encoded list) ────────────────────────────
    # JSON: list of {part_number, rohs_compliant, reach_compliant,
    #                hazardous_substances, status: OK|WARN|FAIL, message}
    rohs_reach_results_json: Optional[str]

    # ── CheckSubstitutionNotes output (JSON-encoded list) ────────────────────
    # JSON: list of {part_number, has_substitution_note, status: OK|FAIL, message}
    substitution_results_json: Optional[str]

    # ── GenerateValidationReport output ──────────────────────────────────────
    # JSON: {summary: {total_items, ok_count, warn_count, fail_count, passed},
    #        line_items: [{part_number, supplier, quantity, status, findings}, ...]}
    validation_report_json: Optional[str]

    # ── Post-process / output ─────────────────────────────────────────────────
    result: Optional[str]  # human-readable validation report text
    formatted_output: Optional[str]  # screened output returned to the caller
    error_code: Optional[str]
