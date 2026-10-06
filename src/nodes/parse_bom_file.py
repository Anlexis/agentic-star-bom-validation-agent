"""AgentCore Platform v1.0"""

# ParseBOMFile — first node in the inner BOM validation workflow.
#
# Parses raw CSV or XML BOM content into structured line items and enforces the
# per-field contract on every parsed value. Parsing is where caller text becomes
# report content, so each column is typed and bounded here rather than at the
# point where it is rendered:
#
#   part_number / spec_ref  — bounded identifier alphabet
#   supplier                — bounded name alphabet
#   quantity                — strict non-negative integer (never coerced)
#   substitution_note       — bounded free text, screened for contact identifiers
#
# A row that violates the contract fails the whole document, naming the column
# and the row index but never the offending value.

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from typing import Any, ClassVar, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from framework.security.pii_detector import detect_pii
from shared.utils.audit_logger import emit_trace_event
from src.services.progress import emit_progress
from src.services.failure_message import EMPTY_INPUT, INPUT_REJECTED

from src.schemas.state import from_json, to_json

# XML tag names recognised as BOM item containers.
_XML_ITEM_TAGS = {"item", "bom_item", "part", "component", "row"}

# Hard ceiling on parsed line items, independent of any configured or
# caller-supplied ceiling. A BOM larger than this is refused rather than
# silently truncated.
_LINE_ITEM_HARD_CAP = 5_000

# Render alphabets. Every value that reaches the report is confined to one of
# these, so caller text cannot introduce markup, control characters or
# structure into the output.
#   identifiers: part numbers and specification codes — letters, digits and the
#     separators OEM catalogues actually use.
#   names: supplier names additionally allow spaces and light punctuation.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/#-]{0,63}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/&,()-]{0,127}$")
_NOTE_RE = re.compile(r"^[^\x00-\x1f\x7f]{0,512}$")

# Strict integer form for quantity: optional leading zeros, digits only. A
# regex rather than int()/float() on purpose — "nan", "inf", "1e5", "0x10",
# " 12 " and "True" all survive some coercion path, and str(float("nan")) is
# the perfectly plausible-looking string "nan". A quantity is either a run of
# digits or it is not a quantity.
_QUANTITY_RE = re.compile(r"^\d{1,9}$")
_MAX_QUANTITY = 1_000_000

# Contact-identifier classes refused in the free-text columns. The Latin-script
# ``name`` class is deliberately excluded: it matches any two consecutive
# capitalised words, which is the shape of an ordinary supplier or component
# label ("Nippon Bearing", "Main Rotor Assembly"), so refusing on it would
# refuse ordinary BOMs.
_CONTACT_TYPES = frozenset({"email", "phone_jp", "phone_us", "ssn_us", "my_number_jp", "credit_card", "name_jp"})

# Document-type and entity declarations turn an XML data file into instructions
# for the parser. Refused here as well as at the caller boundary so the inner
# graph is safe when driven directly.
_XML_DECLARATION_RE = re.compile(r"<!(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


class BOMFieldError(ValueError):
    """A parsed line item violated the per-field contract.

    Carries the column name and 1-based row index only — never the value.

    `contact` marks the subset raised by the contact-identifier screen. A
    misformatted column is a value the caller can correct; a personal
    identifier found in the document is not, so the two are distinguished here
    rather than at the catch site, which cannot tell them apart from the
    message alone.
    """

    def __init__(self, column: str, row: int, detail: str, *, contact: bool = False) -> None:
        super().__init__(f"row {row}: column '{column}' {detail}")
        self.column = column
        self.row = row
        self.contact = contact


def _contact_findings(text: str) -> list[str]:
    """Contact-identifier classes present in a free-text field."""
    return sorted({f["type"] for f in detect_pii(text) if f["type"] in _CONTACT_TYPES})


def _clean_identifier(value: str, column: str, row: int, required: bool) -> str:
    """Validate an identifier column against the bounded identifier alphabet."""
    value = value.strip()
    if not value:
        if required:
            raise BOMFieldError(column, row, "is empty")
        return ""
    if not _IDENTIFIER_RE.match(value):
        raise BOMFieldError(column, row, "contains characters outside the permitted identifier set")
    return value


def _clean_name(value: str, column: str, row: int) -> str:
    """Validate a name column against the bounded name alphabet and contact screen."""
    value = value.strip()
    if not value:
        return ""
    if not _NAME_RE.match(value):
        raise BOMFieldError(column, row, "contains characters outside the permitted name set")
    findings = _contact_findings(value)
    if findings:
        raise BOMFieldError(column, row, f"contains contact identifiers ({', '.join(findings)})", contact=True)
    return value


def _clean_note(value: str, column: str, row: int) -> str:
    """Validate a free-text column: bounded length, no control characters, no contacts."""
    value = value.strip()
    if not value:
        return ""
    if not _NOTE_RE.match(value):
        raise BOMFieldError(column, row, "is too long or contains control characters")
    findings = _contact_findings(value)
    if findings:
        raise BOMFieldError(column, row, f"contains contact identifiers ({', '.join(findings)})", contact=True)
    return value


def _clean_quantity(value: str, column: str, row: int) -> Optional[int]:
    """Type a quantity column strictly. Absent is allowed; malformed is not."""
    value = value.strip()
    if not value:
        return None
    if not _QUANTITY_RE.match(value):
        raise BOMFieldError(column, row, "is not a whole number")
    quantity = int(value)
    if quantity > _MAX_QUANTITY:
        raise BOMFieldError(column, row, f"exceeds the maximum quantity of {_MAX_QUANTITY}")
    return quantity


def _build_item(raw: dict[str, str], row: int) -> dict[str, Any]:
    """Apply the per-field contract to one raw row."""
    return {
        "part_number": _clean_identifier(raw.get("part_number", ""), "part_number", row, True),
        "supplier": _clean_name(raw.get("supplier", ""), "supplier", row),
        "quantity": _clean_quantity(raw.get("quantity", ""), "quantity", row),
        "spec_ref": _clean_identifier(raw.get("spec_ref", ""), "spec_ref", row, False),
        "substitution_note": _clean_note(raw.get("substitution_note", ""), "substitution_note", row),
    }


def _parse_csv_content(bom_content: str, limit: int) -> list[dict[str, Any]]:
    """Parse comma-separated BOM content into validated line items.

    Expects a header row followed by data rows. Columns recognised
    (case-insensitive): part_number, supplier, quantity, spec_ref,
    substitution_note. Unknown columns are ignored. Rows with no part number
    are skipped as blank rows; rows with a malformed value fail the document.
    """
    reader = csv.DictReader(io.StringIO(bom_content.strip()))
    if reader.fieldnames is None:
        return []
    reader.fieldnames = [f.strip().lower().replace(" ", "_") for f in reader.fieldnames]

    items: list[dict[str, Any]] = []
    for row_index, row in enumerate(reader, start=1):
        raw = {k: (v or "") for k, v in row.items() if isinstance(k, str)}
        if not raw.get("part_number", "").strip():
            continue  # blank row
        items.append(_build_item(raw, row_index))
        if len(items) >= limit:
            break
    return items


def _parse_xml_content(bom_content: str, limit: int) -> list[dict[str, Any]]:
    """Parse XML BOM content into validated line items.

    Accepts BOM structures where item elements appear under a root element.
    Recognised item tag names: item, bom_item, part, component, row. Child
    text content or attributes are mapped to the standard BOM fields.
    """
    if _XML_DECLARATION_RE.search(bom_content):
        raise ValueError("document type or entity declarations are not accepted")
    try:
        root = ET.fromstring(bom_content.strip())
    except ET.ParseError as exc:
        raise ValueError(f"XML parse error: {exc}") from exc

    items: list[dict[str, Any]] = []
    row_index = 0
    for elem in root.iter():
        if elem.tag.lower() not in _XML_ITEM_TAGS:
            continue

        def _get(tag: str, node: ET.Element = elem) -> str:
            child = node.find(tag)
            if child is not None and child.text:
                return child.text.strip()
            return (node.get(tag) or "").strip()

        part_number = _get("part_number") or _get("partNumber") or _get("PartNumber")
        if not part_number:
            continue
        row_index += 1
        items.append(
            _build_item(
                {
                    "part_number": part_number,
                    "supplier": _get("supplier") or _get("Supplier"),
                    "quantity": _get("quantity") or _get("Quantity"),
                    "spec_ref": _get("spec_ref") or _get("specRef") or _get("SpecRef"),
                    "substitution_note": _get("substitution_note") or _get("substitutionNote"),
                },
                row_index,
            )
        )
        if len(items) >= limit:
            break
    return items


class ParseBOMFileNode(FunctionNode):
    """Parse raw BOM content (CSV or XML) into validated structured line items.

    Input resolution order:
      1. state["input_context"] — the caller record seeded across the outer→inner
         boundary by the context bridge (src/graph/context_bridge.py);
      2. state["bom_content"] / state["bom_format"] — set by ValidateInputNode
         when the node runs inside the outer graph;
      3. a JSON object in state["user_input"] — direct-invocation fallback.

    Writes parsed_bom_items_json (a JSON-encoded list) to state.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def _resolve_record(self, state: AgentState) -> dict[str, Any]:
        """Collect bom_content / bom_format / max_line_items from the live channel."""
        context = state.get("input_context")
        record: dict[str, Any] = dict(context) if isinstance(context, dict) else {}

        if not record.get("bom_content"):
            record["bom_content"] = state.get("bom_content") or ""
            record.setdefault("bom_format", state.get("bom_format"))
            record.setdefault("max_line_items", state.get("max_line_items"))

        if not record.get("bom_content"):
            user_input = state.get("user_input", "")
            if isinstance(user_input, str) and user_input:
                try:
                    parsed = json.loads(user_input.strip())
                except (json.JSONDecodeError, ValueError, TypeError):
                    parsed = None
                if isinstance(parsed, dict):
                    record["bom_content"] = parsed.get("bom_content") or ""
                    if parsed.get("bom_format"):
                        record["bom_format"] = parsed["bom_format"]
        return record

    def _item_limit(self, state: AgentState, caller_ceiling: Any) -> int:
        """Lowest of the hard cap, the configured ceiling and the caller ceiling."""
        rules = from_json(state.get("agent_config_json")) or {}
        limit = _LINE_ITEM_HARD_CAP
        configured = rules.get("max_line_items") if isinstance(rules, dict) else None
        if isinstance(configured, int) and not isinstance(configured, bool) and configured > 0:
            limit = min(limit, configured)
        if isinstance(caller_ceiling, int) and not isinstance(caller_ceiling, bool) and caller_ceiling > 0:
            limit = min(limit, caller_ceiling)
        return limit

    def execute(self, state: AgentState) -> dict[str, Any]:
        record = self._resolve_record(state)
        bom_content = record.get("bom_content") or ""
        bom_format = (record.get("bom_format") or "csv") or "csv"
        limit = self._item_limit(state, record.get("max_line_items"))

        if not isinstance(bom_content, str) or not bom_content.strip():
            emit_trace_event("parse_bom_file_error", {"reason": "bom_content_missing"}, state)
            emit_progress(EMPTY_INPUT)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": "EMPTY_INPUT",
                "error_log": ["ParseBOMFileNode: bom_content is empty"],
            }

        try:
            if bom_format == "csv":
                items = _parse_csv_content(bom_content, limit)
            else:
                items = _parse_xml_content(bom_content, limit)
        except BOMFieldError as exc:
            emit_trace_event(
                "parse_bom_file_error",
                {"reason": "field_contract_violation", "column": exc.column, "row": exc.row},
                state,
            )
            if exc.contact:
                # A personal identifier found in the document terminates: the
                # document must not be carried further, whatever the caller
                # sends next.
                return {
                    "status": AgentStatus.ERROR.value,
                    "error_log": [f"ParseBOMFileNode: {exc}"],
                }
            emit_progress(INPUT_REJECTED)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": "INVALID_REQUEST",
                "error_log": [f"ParseBOMFileNode: {exc}"],
            }
        except Exception as exc:  # noqa: BLE001 — any parser failure is a rejected document
            emit_trace_event("parse_bom_file_error", {"reason": "parse_failed"}, state)
            emit_progress(INPUT_REJECTED)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": "INVALID_REQUEST",
                "error_log": [f"ParseBOMFileNode: failed to parse BOM — {type(exc).__name__}"],
            }

        if not items:
            emit_trace_event(
                "parse_bom_file_error",
                {"reason": "no_items_found", "bom_format": bom_format},
                state,
            )
            emit_progress(INPUT_REJECTED)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": "INVALID_REQUEST",
                "error_log": ["ParseBOMFileNode: no BOM line items found in content"],
            }

        emit_trace_event(
            "parse_bom_file_complete",
            {"item_count": len(items), "bom_format": bom_format, "item_limit": limit},
            state,
        )

        return {
            "parsed_bom_items_json": to_json(items),
            "bom_content": bom_content,  # propagate into inner state for downstream nodes
            "bom_format": bom_format,
            "status": AgentStatus.SUCCESS.value,
        }
