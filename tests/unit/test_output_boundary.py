"""MFG-C2-012 — the external output boundary.

The agent emits its verdict in two representations, the human-readable text and
the structured report, and both cross the boundary. Each test below is run
against both, and the structured cases put the offending value one and two
levels deep — a scan of top-level strings alone reports nothing there, which is
the failure this file exists to prevent.

Every "the gate catches it" test is paired with a control that proves the probe
itself works, so a green nested case can never be read as "the gate is fine"
when it actually means "the probe never delivered the payload".
"""

import json

import pytest

from framework.schemas.agent_status import AgentStatus

from src.nodes.security_gate_output import (
    _MAX_OUTPUT_CHARS,
    SecurityGateOutputNode,
    _redact_blocked_fields,
    _security_gate_output,
    _walk_strings,
)

_BEARER = "Bearer abcdefghijklmnop0123456789"
_API_KEY = "sk-abcdefghijklmnop0123456789"
_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"


@pytest.fixture(autouse=True)
def _silence_audit(monkeypatch):
    def noop(*args, **kwargs):
        return None

    monkeypatch.setattr("src.nodes.security_gate_output.emit_trace_event", noop, raising=False)


@pytest.fixture
def node():
    return SecurityGateOutputNode()


def _report(part_numbers=("AB-1234",), findings=()):
    return {
        "summary": {
            "total_items": len(part_numbers),
            "ok_count": len(part_numbers),
            "warn_count": 0,
            "fail_count": 0,
            "passed": True,
        },
        "line_items": [
            {
                "part_number": pn,
                "supplier": "SupplierA",
                "quantity": 10,
                "status": "OK",
                "findings": list(findings),
            }
            for pn in part_numbers
        ],
    }


def _text(part_numbers=("AB-1234",), extra_lines=()):
    lines = ["=== BOM Validation Report ===", "Overall: PASS", ""]
    lines += [f"[OK] {pn} | SupplierA | qty: 10" for pn in part_numbers]
    lines += list(extra_lines)
    return "\n".join(lines)


def _state(text, report, **extra):
    state = {
        "result": text,
        "validation_report_json": json.dumps(report) if report is not None else None,
        "session_id": "session-1",
        "correlation_id": "correlation-1",
    }
    state.update(extra)
    return state


# ─────────────────────────────────────────────────────────────────────────────
# The walker
# ─────────────────────────────────────────────────────────────────────────────


class TestNestedTraversal:
    """The scan reaches string leaves at any depth, not only top-level ones."""

    def test_walker_reaches_a_leaf_two_levels_down(self):
        payload = {"report": {"line_items": [{"findings": ["deep value"]}]}}
        assert "deep value" in [value for _, value in _walk_strings(payload)]

    def test_walker_reaches_dictionary_keys(self):
        payload = {"report": {"unexpected key": 1}}
        assert "unexpected key" in [value for _, value in _walk_strings(payload)]

    def test_walker_handles_scalars_and_empty_structures(self):
        assert list(_walk_strings(None)) == []
        assert list(_walk_strings(7)) == []
        assert list(_walk_strings({})) == []
        assert list(_walk_strings([])) == []


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1 — credentials, at the top level AND nested
# ─────────────────────────────────────────────────────────────────────────────


class TestCredentialScan:
    def test_top_level_control_is_detected(self):
        """The control that proves the verifier works at all."""
        assert _security_gate_output(f"report body {_BEARER}") == "bearer_token"

    def test_nested_value_is_detected(self):
        """The same value one level deeper must give the same verdict.

        A gate that scanned only top-level strings returned zero findings here
        while flagging the control above — the two together are what make this
        test meaningful.
        """
        nested = {"report": {"line_items": [{"findings": [f"substitute per {_BEARER}"]}]}}
        assert _security_gate_output(nested) == "bearer_token"

    @pytest.mark.parametrize(
        "secret,expected",
        [
            # The first three are shapes framework.security's own detector also
            # carries, and it is consulted first, so the finding is reported
            # under ITS name — the same name the framework's @final output-safety hook
            # would use if this gate ever let the value through.
            (_API_KEY, "openai_key"),
            (_JWT, "jwt"),
            (_BEARER, "bearer_token"),
            # This one the framework list does not carry; it is a local extra.
            ("api_key = s3cr3tvalue123", "credential_assignment"),
        ],
    )
    def test_each_credential_class_is_detected_nested(self, secret, expected, node):
        nested = {"report": {"line_items": [{"findings": [f"see {secret}"]}]}}
        assert _security_gate_output(nested) == expected
        # Naming the class is not the outcome that matters — withholding is.
        withheld = node.execute(_state(_text(), {"line_items": [{"findings": [f"see {secret}"]}]}))
        assert withheld["status"] == AgentStatus.ERROR.value
        assert withheld["result"] is None
        assert secret not in json.dumps(withheld, default=str)

    def test_clean_report_produces_no_finding(self):
        assert _security_gate_output({"text": _text(), "report": _report()}) is None

    def test_nested_credential_withholds_the_whole_response(self, node):
        """End of the chain: a nested finding withholds both representations.

        `result` is asserted as well as `formatted_output`. Checking only the
        latter passes on a gate that withholds nothing: AgentBaseGraph.get_output
        is `formatted_output or result`, so a refusal that leaves `result`
        standing ships the report the moment the notice is falsy or the delta is
        discarded.
        """
        report = _report(findings=[f"substitute approved under {_BEARER}"])
        result = node.execute(_state(_text(), report))
        assert result["status"] == AgentStatus.ERROR.value
        assert _BEARER not in result["formatted_output"]
        assert result["validation_report_json"] is None
        assert result["result"] is None

    def test_top_level_credential_withholds_the_whole_response(self, node):
        """The control for the case above, at the top level of the text."""
        result = node.execute(_state(_text(extra_lines=[f"note: {_BEARER}"]), _report()))
        assert result["status"] == AgentStatus.ERROR.value
        assert _BEARER not in result["formatted_output"]
        assert result["result"] is None


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 — verbatim caller text
# ─────────────────────────────────────────────────────────────────────────────


class TestBlockedFieldRedaction:
    def test_submitted_document_is_redacted_from_the_text(self, node):
        bom = "part_number,supplier,quantity\nAB-1234,SupplierA,10\n"
        result = node.execute(_state(_text(extra_lines=[bom]), _report(), bom_content=bom))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert bom not in result["formatted_output"]
        assert "[REDACTED]" in result["formatted_output"]

    def test_submitted_document_is_redacted_from_the_structured_report(self, node):
        bom = "part_number,supplier,quantity\nAB-1234,SupplierA,10\n"
        report = _report(findings=[bom])
        result = node.execute(_state(_text(), report, bom_content=bom))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert bom not in result["validation_report_json"]
        assert "[REDACTED]" in result["validation_report_json"]

    def test_short_incidental_overlap_is_not_redacted(self):
        """Negative control: a short request string is not a bulk re-emission."""
        payload = {"text": "report for AB-1234", "report": None}
        out, redacted = _redact_blocked_fields(payload, {"user_input": "AB-1234"})
        assert redacted == []
        assert out["text"] == "report for AB-1234"

    def test_a_clean_report_is_returned_byte_identical(self, node):
        text = _text()
        result = node.execute(_state(text, _report(), bom_content="x" * 40))
        assert result["formatted_output"] == text


# ─────────────────────────────────────────────────────────────────────────────
# Layer 3 — identifier integrity (this template's output invariant)
# ─────────────────────────────────────────────────────────────────────────────


class TestIdentifierIntegrity:
    """This template renders no monetary aggregate, so it enforces no rounding grid.

    The invariant its boundary owes the reader is the opposite one: a precision
    identifier must reach the report byte-identical. Manufacturing identifiers
    are exactly the class that a rounding or normalising pass mangles — a bare
    numeric code has no letters to protect it at all — so the boundary asserts
    the identity rather than assuming it. See docs/02_design.md.
    """

    @pytest.mark.parametrize(
        "part_number",
        [
            "SKF-6205",  # letters plus a grouped digit run
            "SKF-6205-2RS",
            "EAB64785603",  # long unbroken digit run
            "48210",  # purely numeric — nothing protects it but the rule
            "1234",
            "9999",
            "AB-1234-R1",
            "M8X1.25",
            "FLT/AIR-330",
            "HYD200BAR",
        ],
    )
    def test_identifiers_survive_the_boundary_byte_identical(self, node, part_number):
        text = _text((part_number,))
        result = node.execute(_state(text, _report((part_number,))))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["formatted_output"] == text
        assert part_number in result["formatted_output"]
        assert part_number in result["validation_report_json"]

    def test_structural_numbers_are_untouched(self, node):
        """Counts, quantities and section numbers are not rewritten either."""
        text = _text(("AB-1234",), extra_lines=["Total: 12345 items | OK: 9999", "3. Notes"])
        result = node.execute(_state(text, _report()))
        assert result["formatted_output"] == text

    def test_an_identifier_missing_from_the_text_withholds_the_report(self, node):
        """The enforcement direction: a mangled identifier fails closed.

        If a future rendering pass rewrote a part number in one representation
        and not the other, the two would disagree about which part was
        validated — so the response is withheld rather than shipped.
        """
        result = node.execute(_state(_text(("AB-1234",)), _report(("CD-5678",))))
        assert result["status"] == AgentStatus.ERROR.value
        assert result["validation_report_json"] is None
        assert result["result"] is None

    def test_absent_structured_report_does_not_break_the_check(self, node):
        result = node.execute(_state(_text(), None))
        assert result["status"] == AgentStatus.SUCCESS.value


# ─────────────────────────────────────────────────────────────────────────────
# Layer 4 — size cap, and general shape
# ─────────────────────────────────────────────────────────────────────────────


class TestSizeCapAndShape:
    def test_output_beyond_the_cap_is_truncated(self, node):
        result = node.execute(_state("X" * (_MAX_OUTPUT_CHARS + 10_000), None))
        assert len(result["formatted_output"]) < _MAX_OUTPUT_CHARS + 10_000
        assert "truncated at the external boundary" in result["formatted_output"]

    def test_session_identifiers_are_never_echoed(self, node):
        result = node.execute(_state(_text(), _report()))
        assert "session-1" not in result["formatted_output"]
        assert "correlation-1" not in result["formatted_output"]

    def test_empty_result_is_safe(self, node):
        """An empty report is a success with nothing in it — not a withholding.

        `formatted_output == ""` is the falsy value that ACTIVATES
        AgentBaseGraph.get_output's fallback to `result`, so the assertion that
        matters is not the empty string on its own but that the fallback has
        nothing to hand back either. Asserting the empty string alone would pass
        on a gate that withheld a populated report by blanking the notice.
        """
        state = _state("", None)
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["formatted_output"] == ""
        assert (result["formatted_output"] or state["result"] or "") == ""

    def test_unparseable_structured_report_is_not_fatal(self, node):
        state = _state(_text(), None)
        state["validation_report_json"] = "{not json"
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS.value


# ─────────────────────────────────────────────────────────────────────────────
# Envelope containment — the ERROR envelope must not carry the report
# ─────────────────────────────────────────────────────────────────────────────


class TestRefusalClearsTheReport:
    """A refusal must leave nothing behind for the envelope to fall back on.

    `AgentBaseGraph.get_output` is `state.get("formatted_output") or
    state.get("result")` with no status check, so a gate that returns ERROR
    while `result` still holds the report has withheld nothing: the report ships
    inside the ERROR envelope the instant the notice is falsy or the node's
    delta is discarded. These tests assert the delta, not the envelope, so they
    fail on the shipped code regardless of what masks it downstream.
    """

    @pytest.fixture
    def _populated(self):
        """A state carrying every domain payload field, as post_process sees it."""
        return {
            "validated_input": "validate this bill of materials",
            "bom_content": "part_number,supplier,quantity\nAB-1234,SupplierA,10\n",
            "bom_format": "csv",
            "max_line_items": 500,
            "agent_config_json": '{"max_line_items": 500}',
            "parsed_bom_items_json": '[{"part_number": "AB-1234"}]',
            "part_number_results_json": '[{"part_number": "AB-1234", "status": "OK"}]',
            "supplier_results_json": '[{"part_number": "AB-1234", "status": "OK"}]',
            "rohs_reach_results_json": '[{"part_number": "AB-1234", "status": "OK"}]',
            "substitution_results_json": '[{"part_number": "AB-1234", "status": "OK"}]',
        }

    def _credential_refusal(self, node, extra):
        report = _report(findings=[f"substitute approved under {_BEARER}"])
        return node.execute(_state(_text(), report, **extra))

    def _integrity_refusal(self, node, extra):
        return node.execute(_state(_text(("AB-1234",)), _report(("CD-5678",)), **extra))

    @pytest.mark.parametrize("refusal", ["credential", "integrity"])
    def test_every_payload_field_is_overwritten(self, node, _populated, refusal):
        from src.nodes.security_gate_output import _CLEARED_ON_VIOLATION

        driver = self._credential_refusal if refusal == "credential" else self._integrity_refusal
        result = driver(node, _populated)
        assert result["status"] == AgentStatus.ERROR.value
        for field in _CLEARED_ON_VIOLATION:
            assert field in result, f"{field} is in the inventory but the refusal never writes it"
            assert result[field] is None, f"{field} survived the refusal"

    @pytest.mark.parametrize("refusal", ["credential", "integrity"])
    def test_no_report_text_survives_anywhere_in_the_delta(self, node, _populated, refusal):
        driver = self._credential_refusal if refusal == "credential" else self._integrity_refusal
        result = driver(node, _populated)
        serialised = json.dumps(result, default=str)
        assert "BOM Validation Report" not in serialised
        assert _populated["bom_content"] not in serialised
        assert _BEARER not in serialised

    @pytest.mark.parametrize("refusal", ["credential", "integrity"])
    def test_the_notice_is_truthy(self, node, _populated, refusal):
        """A falsy notice would ACTIVATE the fallback it is written to prevent."""
        driver = self._credential_refusal if refusal == "credential" else self._integrity_refusal
        result = driver(node, _populated)
        assert result["formatted_output"], "an empty notice falls through to result"

    @pytest.mark.parametrize("refusal", ["credential", "integrity"])
    def test_inert_provenance_survives_untouched(self, node, _populated, refusal):
        """Enums and counts may stay — they carry no report text and no payload."""
        from src.nodes.security_gate_output import _INERT_ON_VIOLATION

        driver = self._credential_refusal if refusal == "credential" else self._integrity_refusal
        result = driver(node, _populated)
        for field in _INERT_ON_VIOLATION:
            assert field not in result, f"{field} is classified inert but the refusal writes it"

    def test_the_state_inventory_is_pinned(self):
        """A new domain field cannot quietly join the survivors.

        Every field declared in src/schemas/state.py is classified exactly once:
        cleared on a refusal, written by the gate, or explicitly inert. Adding a
        field to the state without classifying it fails here rather than at the
        next boundary review.
        """
        from framework.schemas.agent_state import AgentState

        from src.nodes.security_gate_output import (
            _CLEARED_ON_VIOLATION,
            _INERT_ON_VIOLATION,
            _WRITTEN_ON_VIOLATION,
        )
        from src.schemas.state import State

        classified = set(_CLEARED_ON_VIOLATION) | set(_INERT_ON_VIOLATION) | set(_WRITTEN_ON_VIOLATION)
        domain_fields = set(State.__annotations__) - set(AgentState.__annotations__)
        unclassified = domain_fields - classified
        assert not unclassified, f"unclassified domain state fields: {sorted(unclassified)}"

        # The three framework-declared fields this template re-declares and owns
        # at the boundary are classified too — subtracting AgentState above
        # would otherwise let them drift out of the inventory unnoticed.
        for field in ("result", "validated_input", "formatted_output"):
            assert field in classified, f"{field} must stay in the boundary inventory"

        # Nothing is classified twice, and nothing is classified that the state
        # does not declare.
        assert not (set(_CLEARED_ON_VIOLATION) & set(_INERT_ON_VIOLATION))
        assert classified <= set(State.__annotations__)


class TestViolationMessagesNameLocationsOnly:
    """A violation message may name WHERE, never WHAT.

    The framework's @final output-safety hook raises when a credential appears in ANY
    value the node returns, and the wrapper then discards the whole delta —
    clearing included. Quoting the matched value into the notice is therefore
    not merely untidy; it converts a contained refusal into a bare ERROR partial
    that contains nothing.
    """

    def test_the_notice_names_a_path_and_not_the_secret(self, node):
        report = _report(findings=[f"substitute approved under {_BEARER}"])
        result = node.execute(_state(_text(), report))
        assert _BEARER not in result["formatted_output"]
        assert "line_items[0].findings[0]" in result["formatted_output"]

    def test_the_error_log_names_a_path_and_not_the_secret(self, node):
        report = _report(findings=[f"substitute approved under {_BEARER}"])
        result = node.execute(_state(_text(), report))
        assert _BEARER not in " ".join(result["error_log"])
        assert "line_items[0].findings[0]" in " ".join(result["error_log"])

    def test_caller_influenced_path_components_are_masked(self):
        """A dictionary key inside a structure built from BOM data is caller text."""
        from src.nodes.security_gate_output import _locate_credential

        nested = {"report": {"line_items": [{"AB-1234-supplier-note": f"see {_BEARER}"}]}}
        name, where = _locate_credential(nested)
        assert name == "bearer_token"
        assert "AB-1234-supplier-note" not in where
        assert where == "report.line_items[0].*"

    def test_structural_components_survive_masking(self):
        from src.nodes.security_gate_output import _mask_path

        assert _mask_path("report.line_items[2].findings[0]") == "report.line_items[2].findings[0]"
        assert _mask_path("report.summary.passed") == "report.summary.passed"
        assert _mask_path("text") == "text"
        assert _mask_path("report.whatever_the_caller_named_it") == "report.*"
        assert _mask_path("report.caller_key<key>") == "report.*<key>"


class TestFrameworkDetectorParity:
    """The gate must not be narrower than the detector the framework enforces.

    A credential this gate waves through does not get shipped — the framework's
    own @final hook raises on it a few microseconds later. But the wrapper then
    discards this node's entire delta, INCLUDING the clearing, and the caller
    receives a bare ERROR partial with `result` intact. So a narrower local
    pattern set is itself a bypass, and these are the framework shapes the
    original local list did not carry.
    """

    @pytest.mark.parametrize(
        "secret,expected",
        [
            ("sk_live_" + "abcdefghij0123456789", "stripe_key"),
            ("sk_test_abcdefghij0123456789", "stripe_key"),
            ("AKIA0123456789ABCDEF", "aws_key"),
            ("eyJhbGciOiJIUzI1NiJ9", "jwt"),  # single segment: no dots at all
            ("redis://cache-host:6379/abcdefghij0123456789", "conn_string"),
            ("mongodb://cache-host:27017/abcdefghij0123456789", "conn_string"),
        ],
    )
    def test_framework_known_shapes_are_refused(self, secret, expected):
        nested = {"report": {"line_items": [{"findings": [f"see {secret}"]}]}}
        assert _security_gate_output(nested) == expected

    @pytest.mark.parametrize(
        "secret,expected",
        [
            ("pk-ABCDEFGHIJKLMNOP0123", "api_key_pattern"),
            ("sk-abcdefghij01234567", "api_key_pattern"),  # 18 chars: under the framework's 20
            ("api_key = abcdefghij0123", "credential_assignment"),
        ],
    )
    def test_local_extras_still_apply(self, secret, expected):
        """The local set adds shapes the framework list does not carry."""
        nested = {"report": {"line_items": [{"findings": [f"see {secret}"]}]}}
        assert _security_gate_output(nested) == expected

    def test_a_clean_report_is_still_clean_under_both_detectors(self):
        """Negative control: the widened scan does not refuse ordinary BOM data."""
        assert _security_gate_output({"text": _text(), "report": _report()}) is None

    @pytest.mark.parametrize(
        "part_number",
        ["SKF-6205", "EAB64785603", "48210", "M8X1.25", "FLT/AIR-330", "HYD200BAR"],
    )
    def test_ordinary_manufacturing_identifiers_are_not_credentials(self, part_number):
        assert _security_gate_output({"text": _text((part_number,)), "report": _report((part_number,))}) is None


class TestEnvelopeCannotFallBackOnAFailure:
    """The other half of the fix, at the graph's own output contract.

    The gate can only clear on the paths where its delta lands. When the
    framework's @final output-safety hook raises, BaseNode.__call__ discards the delta and
    returns a bare ERROR partial — status, error_log, node_history,
    execution_time and nothing else. The trust-gate denial branch and a pre_process
    rejection have the same shape. On every one of them the un-gated `result`
    is still sitting in state, and the framework's `formatted_output or result`
    hands it straight back.
    """

    @pytest.fixture
    def agent(self):
        from src.graph.graph import ManufacturingBOMValidationAgent

        return ManufacturingBOMValidationAgent()

    def _bare_error_state(self):
        """Exactly the shape BaseNode.__call__ leaves behind when a node raises."""
        return {
            "result": _text(),
            "status": AgentStatus.ERROR.value,
            "error_log": ["[SecurityGateOutputNode] output gate: credential pattern detected"],
            "node_history": ["SecurityGateOutputNode"],
            "execution_time": {"SecurityGateOutputNode": 0.01},
        }

    def test_a_discarded_gate_delta_does_not_ship_the_report(self, agent):
        state = self._bare_error_state()
        assert agent.get_output(state)["output"] is None

    def test_an_empty_notice_does_not_ship_the_report(self, agent):
        """`""` is falsy, so the framework's `or` would fall through to result."""
        state = self._bare_error_state()
        state["formatted_output"] = ""
        assert agent.get_output(state)["output"] is None

    def test_a_real_notice_is_still_delivered_on_a_failure(self, agent):
        """The control: withholding must not become "return nothing, always"."""
        state = self._bare_error_state()
        state["formatted_output"] = "[REPORT WITHHELD: ...]"
        assert agent.get_output(state)["output"] == "[REPORT WITHHELD: ...]"

    def test_the_success_path_is_untouched(self, agent):
        """The clean-path control: a successful report is still returned in full."""
        state = {
            "result": _text(),
            "formatted_output": _text(),
            "status": AgentStatus.SUCCESS.value,
            "node_history": ["SecurityGateOutputNode"],
        }
        assert agent.get_output(state)["output"] == _text()

    def test_success_still_falls_back_to_result_when_the_gate_wrote_nothing(self, agent):
        """The framework's own fallback is preserved where it is legitimate."""
        state = {"result": _text(), "status": AgentStatus.SUCCESS.value, "node_history": []}
        assert agent.get_output(state)["output"] == _text()


class TestInnerGraphOutputShape:
    """The inner boundary, for the same reason and with its own proof.

    BOMValidationGraphNode sets error_strategy = "propagate", so an inner ERROR
    raises SubgraphError before merge_output() is called and this branch is not
    reachable through /invoke today. It is asserted directly rather than left as
    the one thing standing between a strategy change and a leak — and, being
    unreachable at runtime, it masks no mutant of the two guards above.
    """

    @pytest.fixture
    def inner(self):
        from src.graph.domain_workflow_graph import BOMValidationWorkflowGraph

        return BOMValidationWorkflowGraph()

    def test_a_failed_inner_run_surfaces_no_report(self, inner):
        state = {
            "result": _text(),
            "validation_report_json": json.dumps(_report()),
            "status": AgentStatus.ERROR.value,
        }
        out = inner.get_output(state)
        assert out["output"] is None
        assert out["report"] is None
        assert out["status"] == AgentStatus.ERROR.value

    def test_a_successful_inner_run_still_surfaces_both_representations(self, inner):
        """The control: the success path must still carry the work across."""
        state = {
            "result": _text(),
            "validation_report_json": json.dumps(_report()),
            "status": AgentStatus.SUCCESS.value,
        }
        out = inner.get_output(state)
        assert out["output"] == _text()
        assert out["report"] == json.dumps(_report())
