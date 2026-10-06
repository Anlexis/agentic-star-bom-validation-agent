"""AgentCore Platform v1.0"""

# SecurityGateOutput — post_process backbone slot: the external-output boundary
# for the BOM validation report.
#
# The agent emits the report in TWO representations — the human-readable text
# and the structured JSON report — and both cross the boundary. Every layer
# below therefore runs over both; a representation the gate does not walk is a
# representation it does not protect, and the structured report nests its
# caller-derived text one and two levels deep (line_items[].findings[]), where
# a scan of top-level strings alone sees nothing.
#
# Four independent layers, in order:
#
#   (1) credential scan — API keys, JWTs, Bearer tokens and password
#       assignments anywhere in either representation withhold the response
#       entirely (sanitised stub, status=ERROR);
#   (2) verbatim caller-text redaction — the report is a set of verdicts
#       computed from the BOM, so a verbatim embedding of the submitted
#       document or the raw request text is bulk re-emission, not a feature:
#       any such embedding is replaced with [REDACTED];
#   (3) identifier integrity — every part number in the structured report must
#       appear byte-identical in the text report. This template renders no
#       monetary aggregate, so it carries no rounding grid; the invariant its
#       output boundary owes the reader is the opposite one, that a precision
#       identifier is never rewritten (see docs/02_design.md);
#   (4) size cap — a report longer than the cap is truncated, so a malformed
#       upstream state cannot turn the response into a bulk BOM dump.
#
# The domain output gate is the module-level function `_security_gate_output`
# called from inside execute() — NOT an instance method on the node class. The
# framework auto-wraps node instance-method gate hooks, and a wrapped hook
# returns None on the clean path, which the graph then passes on as the next
# node's state.
#
# Returns ONLY the state keys this node writes (partial-dict contract).
#
# ── Refusal contract ─────────────────────────────────────────────────────────
#
# AgentBaseGraph.get_output() is `state.get("formatted_output") or
# state.get("result")` — there is NO status check. A refusal that returns
# ERROR without overwriting `result` therefore ships the un-gated report inside
# the ERROR envelope, and a falsy `formatted_output` ("" or an absent key)
# ACTIVATES that fallback rather than suppressing it.
#
# So every refusal below goes through _withheld(), which
#   (a) writes a TRUTHY notice into formatted_output, and
#   (b) overwrites `result` and EVERY domain field carrying report text or a
#       caller payload — the _CLEARED_ON_VIOLATION inventory.
#
# Fields left standing are inert provenance only (a format enum, a caller
# ceiling). The two inventories together are pinned against src/schemas/state.py
# by tests/unit/test_output_boundary.py, so a domain field added later cannot
# quietly join the survivors.
#
# The clearing is necessary but NOT sufficient on its own: when the framework's
# own @final output-safety gate raises, BaseNode.__call__ discards this node's whole delta
# and returns a bare ERROR partial that clears nothing. That residual hole is
# closed at the other end, in ManufacturingBOMValidationAgent.get_output().

import json
import logging
import re
from typing import Any, ClassVar, Iterator, List, Optional, Tuple

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from framework.security.credential_detector import detect_credentials
from shared.utils.audit_logger import emit_trace_event
from src.services.failure_message import EMPTY_INPUT, INPUT_REJECTED, INVALID_VALUE, TOO_LONG

logger = logging.getLogger(__name__)

# Maximum allowed output size. A validation report is normally a few KB; a much
# larger one means raw BOM data reached the response.
_MAX_OUTPUT_CHARS = 50_000

_TRUNCATION_NOTICE = "\n[Output truncated at the external boundary]"

# EXTRA credential patterns, layered on top of framework.security's own
# detect_credentials(). The framework list is the authoritative one and is
# consulted first: a local set narrower than the framework's is itself a bypass,
# because the value clears this gate, the framework's @final output-safety hook then raises
# inside the wrapper, and the wrapper discards this node's delta — including its
# clearing. What the four below add on top of the framework list: pk-/ak- keys,
# sk- keys shorter than the framework's 20-character floor, Bearer tokens
# shorter than its 16, and keyword=value credential assignments. The jwt entry
# is subsumed by the framework's (which needs no dot separators) and is kept
# only so the local list still reads as a complete statement of intent.
_CREDENTIAL_PATTERNS: List[Tuple[str, str]] = [
    (r"(?:sk|pk|ak)-[A-Za-z0-9]{16,}", "api_key_pattern"),
    (r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "jwt_pattern"),
    (r"Bearer\s+[A-Za-z0-9_\-\.]{8,}", "bearer_token"),
    (
        r"(?:password|passwd|secret|api_key|token|access_key|private_key)\s*[:=]\s*\S{8,}",
        "credential_assignment",
    ),
]

# State fields that must never be embedded verbatim in the response. The report
# is a set of computed verdicts; the submitted document or the raw request text
# reappearing verbatim means caller-supplied content reached the external
# surface unprocessed.
_BLOCKED_FIELDS = frozenset({"user_input", "validated_input", "bom_content"})

# Only substantial values are matched, so a short incidental overlap between a
# request string and a verdict line is not redacted.
_MIN_BLOCKED_VALUE_CHARS = 10

_REDACTION_PLACEHOLDER = "[REDACTED]"

# Domain state fields overwritten on EVERY refusal. Each one carries either
# report text or a caller/agent payload, and `result` in particular is what
# AgentBaseGraph.get_output() falls back to when formatted_output is falsy.
_CLEARED_ON_VIOLATION: Tuple[str, ...] = (
    "result",
    "validated_input",
    "bom_content",
    "agent_config_json",
    "parsed_bom_items_json",
    "part_number_results_json",
    "supplier_results_json",
    "rohs_reach_results_json",
    "substitution_results_json",
    "validation_report_json",
)

# Inert provenance kept across a refusal: a format enum, a caller-supplied
# ceiling, and the reason code. None carries report text or caller document
# content — the reason code is a closed set of markers this repo defines, never
# caller text, and clearing it would leave the caller a body with nothing
# naming what to correct. Pinned by name so a future field cannot join them
# without failing the inventory test.
_INERT_ON_VIOLATION: Tuple[str, ...] = ("bom_format", "max_line_items", "error_code")

# Written explicitly by _withheld() rather than cleared.
_WRITTEN_ON_VIOLATION: Tuple[str, ...] = ("formatted_output",)

# Structural components of the screened payload. Anything else in a violation
# path is caller-influenced text — a dictionary key built from BOM data, say —
# and is masked before it reaches a log line or the response.
_KNOWN_PATH_COMPONENTS = frozenset(
    {
        "$",
        "text",
        "report",
        "summary",
        "total_items",
        "ok_count",
        "warn_count",
        "fail_count",
        "passed",
        "line_items",
        "part_number",
        "supplier",
        "quantity",
        "status",
        "findings",
    }
)

_MASKED_COMPONENT = "*"
_KEY_MARKER = "<key>"


def _walk_strings(payload: Any, path: str = "") -> Iterator[Tuple[str, str]]:
    """Yield (path, value) for every string leaf in a nested structure.

    Mappings, sequences and scalars are all traversed, so a value nested inside
    the structured report's line items is visited exactly like a top-level one.
    Dictionary KEYS are yielded as well: a key is caller-influenced text in any
    structure built from caller data.
    """
    if isinstance(payload, str):
        yield path or "$", payload
    elif isinstance(payload, dict):
        for key, value in payload.items():
            child = f"{path}.{key}" if path else str(key)
            if isinstance(key, str):
                yield f"{child}<key>", key
            yield from _walk_strings(value, child)
    elif isinstance(payload, (list, tuple)):
        for index, value in enumerate(payload):
            yield from _walk_strings(value, f"{path}[{index}]")


def _mask_path(path: str) -> str:
    """Reduce a walk path to structure, masking caller-influenced components.

    A violation message may name a LOCATION but never the matched value, and a
    raw path is not automatically a location: `_walk_strings` yields dictionary
    keys, and a key inside a structure built from BOM data is caller text.
    Component names the report's own schema defines survive; every other one
    becomes `*`. List indices and the `<key>` marker are structure and are kept.
    """
    masked: List[str] = []
    for raw in path.split("."):
        is_key = raw.endswith(_KEY_MARKER)
        body = raw[: -len(_KEY_MARKER)] if is_key else raw
        indices = ""
        while body.endswith("]") and "[" in body:
            body, _, index = body.rpartition("[")
            indices = f"[{index}" + indices
        name = body if body in _KNOWN_PATH_COMPONENTS else _MASKED_COMPONENT
        masked.append(f"{name}{indices}{_KEY_MARKER if is_key else ''}")
    return ".".join(masked)


def _locate_credential(content: Any) -> Optional[Tuple[str, str]]:
    """Return (violation_name, masked_path) for the first credential found.

    The FRAMEWORK's detector runs first on every string leaf, because it is the
    set the framework's own @final output-safety hook enforces a few microseconds later:
    a value this gate waves through and the framework then rejects costs us the
    whole delta, clearing included. The local extras run afterwards for the
    shapes the framework list does not carry.

    Only the finding TYPE and a masked path are returned — never the matched
    value, which would re-emit the credential into a log line or the response.
    """
    for path, value in _walk_strings(content):
        framework_findings = detect_credentials(value)
        if framework_findings:
            return str(framework_findings[0]["type"]), _mask_path(path)
        for pattern, name in _CREDENTIAL_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return name, _mask_path(path)
    return None


def _security_gate_output(content: Any) -> Optional[str]:
    """Scan output for disallowed credential/secret patterns.

    Accepts a string or any nested structure and returns the first violation
    name found, or None when the output is clean. Module-level function (not a
    node instance method) — the framework auto-wraps node instance methods on
    the real invoke path, so the gate must live at module level.
    """
    located = _locate_credential(content)
    return located[0] if located else None


def _withheld(notice: str, error: str) -> dict[str, Any]:
    """Build a refusal delta that withholds the response instead of shipping it.

    Two halves, and the response is only withheld when both are present:

    * a TRUTHY `formatted_output` notice — an empty string here would be falsy
      and would hand `state["result"]` straight to AgentBaseGraph.get_output();
    * every field in _CLEARED_ON_VIOLATION overwritten with None, so the report
      text and the caller's document do not survive the refusal in state.
    """
    delta: dict[str, Any] = dict.fromkeys(_CLEARED_ON_VIOLATION)
    delta["formatted_output"] = notice
    delta["status"] = AgentStatus.ERROR.value
    delta["error_log"] = [error]
    return delta


def _redact_blocked_fields(payload: Any, state: AgentState) -> Tuple[Any, List[str]]:
    """Replace verbatim embeddings of caller-derived state text with a placeholder.

    Returns (sanitised_payload, redacted_field_names). Walks nested structures,
    so an embedding inside the structured report is redacted exactly like one
    in the text.
    """
    values = {
        field: state.get(field)
        for field in sorted(_BLOCKED_FIELDS)
        if isinstance(state.get(field), str) and len(str(state.get(field))) > _MIN_BLOCKED_VALUE_CHARS
    }
    if not values:
        return payload, []

    redacted: List[str] = []

    def _scrub(node: Any) -> Any:
        if isinstance(node, str):
            out = node
            for field, value in values.items():
                if value in out:
                    out = out.replace(value, _REDACTION_PLACEHOLDER)
                    if field not in redacted:
                        redacted.append(field)
            return out
        if isinstance(node, dict):
            return {k: _scrub(v) for k, v in node.items()}
        if isinstance(node, list):
            return [_scrub(v) for v in node]
        return node

    return _scrub(payload), sorted(redacted)


def _identifier_integrity_violations(text: str, report: Any) -> List[str]:
    """Return part numbers present in the structured report but not in the text.

    This template renders no monetary aggregate, so it enforces no rounding
    grid. The invariant it does owe the reader is that a precision identifier —
    a part number, a specification code — reaches the report byte-identical to
    the way it was submitted. Rendering both representations from the same
    line items and then checking that every identifier survives into the text
    makes that invariant enforced rather than merely intended.
    """
    if not isinstance(report, dict):
        return []
    line_items = report.get("line_items")
    if not isinstance(line_items, list):
        return []
    missing = []
    for item in line_items:
        if not isinstance(item, dict):
            continue
        part_number = item.get("part_number")
        if isinstance(part_number, str) and part_number and part_number not in text:
            missing.append(part_number)
    return missing


# Reason code -> the sentence the caller reads. A code with no entry falls
# back to the generic one rather than leaking the code itself.
_DEGRADED_MESSAGES = {
    "EMPTY_INPUT": EMPTY_INPUT,
    "QUESTION_TOO_LONG": TOO_LONG,
    "INVALID_REQUEST": INVALID_VALUE,
}


class SecurityGateOutputNode(FunctionNode):
    """External output boundary for the BOM Validation Agent (post_process slot).

    Declared ANONYMOUS — caller trust was already enforced at ValidateInputNode.

    Input state keys:
        result:                 str — human-readable validation report text
        validation_report_json: str — JSON-encoded structured report

    Output state keys (partial dict):
        formatted_output:       str
        validation_report_json: str  (sanitised)
        status:                 str
        error_log:              list[str]  (only on ERROR)

    On a refusal the delta additionally overwrites every field in
    _CLEARED_ON_VIOLATION with None — see the refusal contract at the top of
    this module. Returning ERROR while leaving `result` populated would ship
    the un-gated report through AgentBaseGraph.get_output()'s
    `formatted_output or result` fallback.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> dict[str, Any]:
        # A run declined upstream has nothing to format. Render the reason as
        # the caller-facing body and carry the marker onward.
        marker = state.get("error_code")
        if marker:
            message = _DEGRADED_MESSAGES.get(marker, INPUT_REJECTED)
            emit_trace_event("post_process_degraded", {"reason": marker}, state)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": marker,
                "formatted_output": message,
                # No BOM was validated, so there is no report to publish.
                "validation_report_json": None,
            }
        result = state.get("result") or ""
        raw_report = state.get("validation_report_json")
        session_id = state.get("session_id", "")
        correlation_id = state.get("correlation_id", "")

        report: Any = None
        if isinstance(raw_report, str) and raw_report:
            try:
                report = json.loads(raw_report)
            except (json.JSONDecodeError, ValueError):
                report = None

        payload: dict[str, Any] = {"text": result, "report": report}

        # ── Layer 1: credential scan across both representations ──────────────
        located = _locate_credential(payload)
        if located:
            violation, where = located
            logger.error(
                "SecurityGateOutputNode: credential pattern detected in output at %s",
                where,
            )
            emit_trace_event(
                "bom_report_credential_violation",
                {"violation": violation, "location": where},
                state,
            )
            return _withheld(
                notice=(
                    "[REPORT WITHHELD: the validation report contained a disallowed "
                    f"pattern ({violation}) at {where}. Contact the BOM data owner.]"
                ),
                error=f"SecurityGateOutputNode: credential pattern detected — {violation} at {where}",
            )

        # ── Layer 2: verbatim caller-text redaction ───────────────────────────
        payload, redacted_fields = _redact_blocked_fields(payload, state)
        sanitised_text: str = payload["text"]
        sanitised_report = payload["report"]
        if redacted_fields:
            logger.error(
                "SecurityGateOutputNode: caller-supplied text embedded verbatim in output — %s",
                ", ".join(redacted_fields),
            )
            emit_trace_event("bom_report_blocked_field_redaction", {"fields": redacted_fields}, state)

        # ── Layer 3: identifier integrity ─────────────────────────────────────
        missing = _identifier_integrity_violations(sanitised_text, sanitised_report)
        if missing:
            logger.error(
                "SecurityGateOutputNode: %d part number(s) did not survive into the text report",
                len(missing),
            )
            emit_trace_event(
                "bom_report_identifier_integrity_violation",
                {"missing_count": len(missing)},
                state,
            )
            return _withheld(
                notice=(
                    "[REPORT WITHHELD: part numbers were not rendered byte-identical " "in the validation report.]"
                ),
                error=(
                    "SecurityGateOutputNode: identifier integrity check failed for " f"{len(missing)} part number(s)"
                ),
            )

        # ── Layer 4: size cap ─────────────────────────────────────────────────
        was_truncated = len(sanitised_text) > _MAX_OUTPUT_CHARS
        if was_truncated:
            sanitised_text = sanitised_text[:_MAX_OUTPUT_CHARS] + _TRUNCATION_NOTICE
            emit_trace_event("bom_report_truncated", {"limit": _MAX_OUTPUT_CHARS}, state)

        # Audit event for supplier-control record keeping.
        emit_trace_event(
            "bom_validation_audit",
            {
                "session_id": session_id,
                "correlation_id": correlation_id,
                "output_length": len(sanitised_text),
                "was_truncated": was_truncated,
                "redacted_fields": len(redacted_fields),
                "output_gate": "applied",
                "compliance_scheme": "ISO_9001_8.4",
            },
            state,
        )

        return {
            "formatted_output": sanitised_text,
            "validation_report_json": (
                json.dumps(sanitised_report, ensure_ascii=False) if sanitised_report is not None else None
            ),
            "status": AgentStatus.SUCCESS.value,
        }
