"""AgentCore Platform v1.0"""

# ValidateInput — pre_process backbone slot.
#
# This node owns the caller-data contract: everything the caller controls is
# checked here against explicit bounds before any domain node sees it, and a
# rejection names the offending FIELD, never the offending value.
#
# Primary path: the BOM record arrives on input_context (the structured
#   invocation channel) as {"bom_content": ..., "bom_format": ...,
#   "max_line_items": ...}.
# Fallback path: user_input is a JSON object with the same keys. This exists
#   for direct invocation and test harnesses. It is lossy by construction —
#   see the transit-integrity check below — so callers with real BOM data use
#   the context channel.

import json
import math
import re
from typing import Any, ClassVar, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from framework.security.pii_detector import detect_pii
from shared.utils.audit_logger import emit_trace_event
from src.services.failure_message import INPUT_REJECTED
from src.services.progress import emit_progress

# Reject BOM documents larger than 500 KB.
_MAX_BOM_BYTES = 500_000

# Caller-narrowable ceiling on processed line items. The caller may lower the
# configured ceiling, never raise it; the configured value is the hard bound.
_MIN_LINE_ITEMS = 1
_MAX_LINE_ITEMS = 5_000

_SUPPORTED_FORMATS = ("csv", "xml")

# Executable or markup constructs that have no place in a BOM document. Each
# pattern requires the construct's real syntax rather than a bare keyword, so
# ordinary engineering prose is unaffected: "Evaluate the alternative part" and
# "system replacement scheduled" do not match, while "eval(" and "<script" do.
_INJECTION_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"</?script\b", "script_tag"),
    (r"<\?php\b", "php_open_tag"),
    (r"\b(?:system|exec|eval|popen|compile)\s*\(", "code_execution_call"),
    (r"__import__\s*\(", "dynamic_import_call"),
    # XML BOMs are parsed as data. A document type declaration or an entity
    # declaration turns a data file into an instruction to the parser
    # (entity expansion, external references) — refused before parsing.
    (r"<!DOCTYPE\b", "doctype_declaration"),
    (r"<!ENTITY\b", "entity_declaration"),
)

_COMPILED_INJECTION: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), name) for pattern, name in _INJECTION_PATTERNS
)

# Contact-identifier classes screened across the whole BOM document. Restricted
# to the two detector classes whose syntax cannot be produced by a part number
# or a specification code: an address needs an "@", and the Japanese-name class
# only fires after an explicit name label. The digit-shaped classes (phone,
# national identifiers, card numbers) are screened per FIELD after parsing,
# where a digit run is unambiguously not an identifier — screening those over
# the raw document would refuse legitimate BOMs whose part codes are grouped
# digit runs.
_DOCUMENT_CONTACT_TYPES = frozenset({"email", "name_jp"})

# The framework input gate masks detected personal names in user_input before
# execute() runs, and a two-word supplier or component label has exactly that
# shape. A BOM that arrived through the user_input fallback carrying this
# sentinel was altered in transit, so its supplier names — and therefore the
# Approved-Supplier-List verdicts computed from them — cannot be trusted.
_TRANSIT_MASK_SENTINEL = "[MASKED]"


def _finite_int_in_range(value: Any, lo: int, hi: int) -> Optional[int]:
    """Return value as an int when it is a real, finite integer within [lo, hi].

    Returns None for everything else, and the caller then fails CLOSED. The
    cases that matter and the reason each is rejected explicitly:

    * ``bool`` — ``isinstance(True, int)`` is True in Python, so a JSON ``true``
      would otherwise arrive as 1.
    * ``str`` — ``"12345"``, ``"nan"`` and ``"inf"`` all survive a
      ``float()``-based check; coercing a string is not typing it.
    * ``float("nan")`` / ``float("inf")`` — both parse, and both make every
      range comparison False, so an unchecked non-finite value silently
      disables the bound it was supposed to enforce. Python's json module
      emits and accepts bare ``NaN`` / ``Infinity``, so these arrive over the
      wire even though they are not valid JSON.
    * non-integral floats and out-of-range magnitudes.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float):
        if not math.isfinite(value) or value != int(value):
            return None
        value = int(value)
    return value if lo <= value <= hi else None


def _document_contact_findings(text: str) -> list[str]:
    """Return the collision-free contact-identifier classes present in a document.

    Findings are refused, never masked: masking would leave a BOM whose
    supplier and component labels had been rewritten, which is worse than a
    refusal because the resulting report reads as authoritative.
    """
    return sorted({f["type"] for f in detect_pii(text) if f["type"] in _DOCUMENT_CONTACT_TYPES})


class ValidateInputNode(FunctionNode):
    """Caller-data contract for the BOM Validation Agent (pre_process slot).

    Validates, in order:
      - user_input is a non-empty string
      - bom_content is present on input_context (or the user_input JSON fallback)
      - bom_content is a string within the 500 KB size bound
      - bom_content was not altered in transit on the fallback channel
      - bom_format is one of the supported document formats
      - max_line_items, when supplied, is a finite integer inside its bounds
      - bom_content carries no executable or markup construct
      - bom_content carries no contact identifier

    On rejection the node returns ERROR with a message naming the field; the
    rejected value is never copied into the error log or the audit event.

    The refusal lives in this node rather than depending on a platform gate:
    the agent must behave the same way wherever it runs, so the check is
    provable by calling execute() directly, with no framework wrapper in front.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def _reject(self, state: AgentState, reason: str, message: str, code: str = "INVALID_REQUEST") -> dict[str, Any]:
        """Emit the audit event and return the ERROR delta. Values are never echoed."""
        emit_trace_event("validate_input_rejected", {"reason": reason}, state)
        if code:
            # A value the caller can correct: the run COMPLETES carrying the
            # reason so the request can be sent again on the same conversation.
            emit_progress(INPUT_REJECTED)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": code,
                "error_log": [f"ValidateInputNode: {message}"],
            }
        return {
            "status": AgentStatus.ERROR.value,
            "error_log": [f"ValidateInputNode: {message}"],
        }

    def execute(self, state: AgentState) -> dict[str, Any]:
        user_input = state.get("user_input", "")
        input_context = state.get("input_context") or {}
        if not isinstance(input_context, dict):
            return self._reject(state, "input_context_not_mapping", "input_context must be an object")

        # ── user_input presence check ─────────────────────────────────────────
        if not isinstance(user_input, str) or not user_input.strip():
            return self._reject(state, "user_input_empty", "user_input is empty or missing", code="EMPTY_INPUT")

        # ── BOM record extraction ─────────────────────────────────────────────
        bom_content = input_context.get("bom_content")
        bom_format_raw = input_context.get("bom_format")
        max_line_items_raw = input_context.get("max_line_items")
        from_fallback_channel = False

        if bom_content is None:
            try:
                parsed = json.loads(user_input.strip())
            except (json.JSONDecodeError, ValueError, TypeError):
                parsed = None
            if isinstance(parsed, dict) and parsed.get("bom_content") is not None:
                bom_content = parsed.get("bom_content")
                from_fallback_channel = True
                if bom_format_raw is None:
                    bom_format_raw = parsed.get("bom_format")
                if max_line_items_raw is None:
                    max_line_items_raw = parsed.get("max_line_items")

        if bom_content is None:
            return self._reject(
                state,
                "bom_content_missing",
                "bom_content is missing (supply it on input_context)",
                code="EMPTY_INPUT",
            )
        if not isinstance(bom_content, str) or not bom_content.strip():
            return self._reject(state, "bom_content_invalid", "bom_content must be a non-empty string")

        # ── size bound ────────────────────────────────────────────────────────
        if len(bom_content.encode("utf-8")) > _MAX_BOM_BYTES:
            return self._reject(
                state,
                "bom_content_too_large",
                "bom_content exceeds the 500 KB size bound",
                code="QUESTION_TOO_LONG",
            )

        # ── transit integrity on the fallback channel ─────────────────────────
        if from_fallback_channel and _TRANSIT_MASK_SENTINEL in bom_content:
            return self._reject(
                state,
                "bom_content_altered_in_transit",
                "bom_content was altered in transit on the user_input channel; "
                "resubmit the BOM record on input_context",
            )

        # ── document format ───────────────────────────────────────────────────
        if bom_format_raw is None or bom_format_raw == "":
            bom_format = "csv"
        elif isinstance(bom_format_raw, str):
            bom_format = bom_format_raw.strip().lower()
        else:
            return self._reject(state, "bom_format_invalid", "bom_format must be a string")
        if bom_format not in _SUPPORTED_FORMATS:
            return self._reject(
                state,
                "bom_format_unsupported",
                "bom_format is not a supported document format ('csv' or 'xml')",
            )

        # ── caller line-item ceiling ──────────────────────────────────────────
        max_line_items: Optional[int] = None
        if max_line_items_raw is not None:
            max_line_items = _finite_int_in_range(max_line_items_raw, _MIN_LINE_ITEMS, _MAX_LINE_ITEMS)
            if max_line_items is None:
                return self._reject(
                    state,
                    "max_line_items_out_of_bounds",
                    f"max_line_items must be an integer between {_MIN_LINE_ITEMS} " f"and {_MAX_LINE_ITEMS}",
                )

        # ── executable / markup constructs ────────────────────────────────────
        for compiled, name in _COMPILED_INJECTION:
            if compiled.search(bom_content):
                return self._reject(
                    state,
                    "bom_content_disallowed_construct",
                    f"bom_content contains a disallowed construct ({name})",
                    # An active-content construct is not a value the caller
                    # corrects by reformatting: the refusal terminates.
                    code="",
                )

        # ── contact identifiers ───────────────────────────────────────────────
        contact_findings = _document_contact_findings(bom_content)
        if contact_findings:
            return self._reject(
                state,
                "bom_content_contact_identifier",
                "bom_content contains contact identifiers "
                f"({', '.join(contact_findings)}); remove them before validation",
                # A personal-identifier finding terminates: the document must
                # not be carried further, whatever the caller does next.
                code="",
            )

        emit_trace_event(
            "validate_input_accepted",
            {
                "bom_format": bom_format,
                "content_length": len(bom_content),
                "channel": "user_input" if from_fallback_channel else "input_context",
                "max_line_items_supplied": max_line_items is not None,
            },
            state,
        )

        return {
            "validated_input": user_input.strip(),
            "bom_content": bom_content,
            "bom_format": bom_format,
            "max_line_items": max_line_items,
            "status": AgentStatus.SUCCESS.value,
        }
