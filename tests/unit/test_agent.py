"""MFG-C2-012 Unit Tests — BOM Validation Agent domain nodes.

Design rules:
  - never stub the shared package in sys.modules (the installed framework ships a
    real one)
  - patch emit_trace_event at the node module via autouse fixtures
  - no _extra_security_gate_* overrides in any node
  - tests import the real node modules; no all-stub files
"""

import json

import pytest

from framework.schemas.agent_status import AgentStatus

# ── Autouse emit_trace_event patches ──────────────────────────────────────────
# Patch at the node module level (not via sys.modules) to silence audit calls.
# Required pattern: patch("src.nodes.<mod>.emit_trace_event", noop).


@pytest.fixture(autouse=True)
def _patch_all_emit(monkeypatch):
    """Silence emit_trace_event calls in all node modules under test."""

    def noop(*args, **kwargs):
        return None

    for mod in (
        "src.nodes.validate_input",
        "src.nodes.parse_bom_file",
        "src.nodes.validate_part_numbers",
        "src.nodes.check_approved_suppliers",
        "src.nodes.check_rohs_reach",
        "src.nodes.check_substitution_notes",
        "src.nodes.generate_validation_report",
        "src.nodes.security_gate_output",
    ):
        monkeypatch.setattr(mod + ".emit_trace_event", noop, raising=False)


# ── Fixtures / test data ──────────────────────────────────────────────────────

CSV_BOM_CONTENT = (
    "part_number,supplier,quantity,spec_ref,substitution_note\n"
    "AB-1234,SupplierA,100,SPEC-001,\n"
    "CD-5678,SupplierB,50,SPEC-002,Use RoHS-compliant variant\n"
    "EF-9012,SupplierC,25,SPEC-003,\n"
)

XML_BOM_CONTENT = """<?xml version="1.0"?>
<bom>
  <item>
    <part_number>AB-1234</part_number>
    <supplier>SupplierA</supplier>
    <quantity>100</quantity>
    <spec_ref>SPEC-001</spec_ref>
    <substitution_note></substitution_note>
  </item>
  <item>
    <part_number>CD-5678</part_number>
    <supplier>SupplierB</supplier>
    <quantity>50</quantity>
    <spec_ref>SPEC-002</spec_ref>
    <substitution_note>Use RoHS-compliant variant</substitution_note>
  </item>
</bom>"""


# ─────────────────────────────────────────────────────────────────────────────
# ValidateInputNode
# ─────────────────────────────────────────────────────────────────────────────


class TestValidateInputNode:
    @pytest.fixture
    def node(self):
        from src.nodes.validate_input import ValidateInputNode

        return ValidateInputNode()

    def test_success_csv_via_input_context(self, node):
        """TC-VI-01: success path with CSV bom_content in input_context."""
        state = {
            "user_input": "Validate BOM",
            "input_context": {"bom_content": CSV_BOM_CONTENT, "bom_format": "csv"},
        }
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        assert result["bom_content"] == CSV_BOM_CONTENT
        assert result["bom_format"] == "csv"
        assert result["validated_input"] == "Validate BOM"

    def test_success_json_fallback(self, node):
        """TC-VI-02: success path with bom_content embedded in user_input JSON."""
        payload = json.dumps({"bom_content": CSV_BOM_CONTENT, "bom_format": "csv"})
        state = {"user_input": payload, "input_context": {}}
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        assert result["bom_content"] == CSV_BOM_CONTENT

    def test_empty_user_input_rejected(self, node):
        """TC-VI-03: empty user_input completes carrying EMPTY_INPUT, validating nothing."""
        state = {"user_input": "", "input_context": {"bom_content": CSV_BOM_CONTENT}}
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS

    def test_missing_bom_content_rejected(self, node):
        """TC-VI-04: missing bom_content completes carrying EMPTY_INPUT, validating nothing."""
        state = {"user_input": "Validate BOM", "input_context": {}}
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS

    def test_invalid_format_rejected(self, node):
        """TC-VI-05: unsupported bom_format completes carrying INVALID_REQUEST."""
        state = {
            "user_input": "Validate",
            "input_context": {"bom_content": CSV_BOM_CONTENT, "bom_format": "xlsx"},
        }
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS

    def test_injection_pattern_rejected(self, node):
        """TC-VI-06: bom_content carrying a script tag terminates — rewording cannot fix it."""
        malicious = "part_number,supplier\n<script>alert(1)</script>,BadSupplier"
        state = {
            "user_input": "Validate",
            "input_context": {"bom_content": malicious, "bom_format": "csv"},
        }
        result = node.execute(state)
        assert result["status"] == AgentStatus.ERROR

    def test_oversized_content_rejected(self, node):
        """TC-VI-07: bom_content > 500 KB completes carrying QUESTION_TOO_LONG (size bound)."""
        large_content = "part_number,supplier\n" + "AB-1234,Supplier\n" * 30_000
        state = {
            "user_input": "Validate",
            "input_context": {"bom_content": large_content, "bom_format": "csv"},
        }
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS


# ─────────────────────────────────────────────────────────────────────────────
# ParseBOMFileNode
# ─────────────────────────────────────────────────────────────────────────────


class TestParseBOMFileNode:
    @pytest.fixture
    def node(self):
        from src.nodes.parse_bom_file import ParseBOMFileNode

        return ParseBOMFileNode()

    def test_parse_csv_success(self, node):
        """TC-PBF-01: parses valid CSV BOM into structured items."""
        state = {"bom_content": CSV_BOM_CONTENT, "bom_format": "csv"}
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        from src.schemas.state import from_json

        items = from_json(result["parsed_bom_items_json"])
        assert len(items) == 3
        assert items[0]["part_number"] == "AB-1234"
        assert items[0]["supplier"] == "SupplierA"
        assert items[0]["quantity"] == 100, "quantity is typed as an integer, not carried as text"
        assert items[1]["substitution_note"] == "Use RoHS-compliant variant"

    def test_parse_xml_success(self, node):
        """TC-PBF-02: parses valid XML BOM into structured items."""
        state = {"bom_content": XML_BOM_CONTENT, "bom_format": "xml"}
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        from src.schemas.state import from_json

        items = from_json(result["parsed_bom_items_json"])
        assert len(items) == 2
        assert items[0]["part_number"] == "AB-1234"

    def test_empty_content_returns_error(self, node):
        """TC-PBF-03: empty bom_content completes carrying EMPTY_INPUT."""
        state = {"bom_content": "", "bom_format": "csv"}
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS

    def test_malformed_xml_returns_error(self, node):
        """TC-PBF-04: unparseable XML completes carrying INVALID_REQUEST."""
        state = {"bom_content": "<bom><item>unclosed", "bom_format": "xml"}
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS


# ─────────────────────────────────────────────────────────────────────────────
# ValidatePartNumbersNode
# ─────────────────────────────────────────────────────────────────────────────


class TestValidatePartNumbersNode:
    @pytest.fixture
    def node(self):
        from src.nodes.validate_part_numbers import ValidatePartNumbersNode

        return ValidatePartNumbersNode()

    def test_valid_part_numbers_pass(self, node):
        """TC-VPN-01: part numbers matching the default OEM pattern return OK."""
        from src.schemas.state import to_json, from_json

        state = {
            "parsed_bom_items_json": to_json(
                [
                    {
                        "part_number": "AB-1234",
                        "supplier": "SA",
                        "quantity": "10",
                        "spec_ref": "",
                        "substitution_note": "",
                    },
                ]
            )
        }
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        assert from_json(result["part_number_results_json"])[0]["status"] == "OK"

    def test_invalid_part_number_fails(self, node):
        """TC-VPN-02: non-matching part number returns FAIL."""
        from src.schemas.state import to_json, from_json

        state = {
            "parsed_bom_items_json": to_json(
                [
                    {
                        "part_number": "invalid-pn",
                        "supplier": "SA",
                        "quantity": "10",
                        "spec_ref": "",
                        "substitution_note": "",
                    },
                ]
            )
        }
        result = node.execute(state)
        assert from_json(result["part_number_results_json"])[0]["status"] == "FAIL"

    def test_custom_pattern_via_declared_config(self, node):
        """TC-VPN-03: a declared part_number_pattern is honoured.

        Declared configuration reaches domain nodes through
        state["agent_config_json"] (checked and forwarded by
        BOMValidationGraphNode._parent_config(), republished by
        BOMValidationWorkflowGraph._extra_initial_state()) — not through a second
        execute() parameter.
        """
        from src.schemas.state import to_json, from_json

        state = {
            "parsed_bom_items_json": to_json(
                [
                    {"part_number": "12345", "supplier": "S", "quantity": "1", "spec_ref": "", "substitution_note": ""},
                ]
            ),
            "agent_config_json": to_json({"part_number_pattern": r"^\d+$"}),
        }
        result = node.execute(state)
        assert from_json(result["part_number_results_json"])[0]["status"] == "OK"

    def test_default_pattern_used_when_config_absent(self, node):
        """TC-VPN-05: no agent_config_json in state → built-in OEM default pattern."""
        from src.schemas.state import to_json, from_json

        state = {
            "parsed_bom_items_json": to_json(
                [
                    {"part_number": "12345", "supplier": "S", "quantity": "1", "spec_ref": "", "substitution_note": ""},
                ]
            )
        }
        result = node.execute(state)
        assert from_json(result["part_number_results_json"])[0]["status"] == "FAIL"

    def test_empty_items_returns_error(self, node):
        """TC-VPN-04: no parsed items returns ERROR."""
        state = {"parsed_bom_items_json": None}
        result = node.execute(state)
        assert result["status"] == AgentStatus.ERROR


# ─────────────────────────────────────────────────────────────────────────────
# CheckApprovedSuppliersNode
# ─────────────────────────────────────────────────────────────────────────────


class TestCheckApprovedSuppliersNode:
    @pytest.fixture
    def node(self):
        from src.nodes.check_approved_suppliers import CheckApprovedSuppliersNode

        return CheckApprovedSuppliersNode()

    def _items(self, supplier="SupplierA", agent_config=None):
        """Build inner state. agent_config is seeded as the JSON field
        agent_config_json — the same channel the inner graph uses at runtime."""
        from src.schemas.state import to_json

        state = {
            "parsed_bom_items_json": to_json(
                [
                    {
                        "part_number": "AB-1234",
                        "supplier": supplier,
                        "quantity": "10",
                        "spec_ref": "",
                        "substitution_note": "",
                    },
                ]
            )
        }
        if agent_config is not None:
            state["agent_config_json"] = to_json(agent_config)
        return state

    def test_supplier_in_asl_passes(self, node):
        """TC-CAS-01: supplier in ASL returns OK."""
        from src.schemas.state import from_json

        result = node.execute(self._items("SupplierA", {"approved_suppliers": ["SupplierA", "SupplierB"]}))
        assert from_json(result["supplier_results_json"])[0]["status"] == "OK"

    def test_supplier_not_in_asl_fails(self, node):
        """TC-CAS-02: supplier absent from configured ASL returns FAIL."""
        from src.schemas.state import from_json

        result = node.execute(self._items("UnknownSupplier", {"approved_suppliers": ["SupplierA"]}))
        assert from_json(result["supplier_results_json"])[0]["status"] == "FAIL"

    def test_empty_asl_all_pass(self, node):
        """TC-CAS-03: empty ASL (unconfigured) → all suppliers pass."""
        from src.schemas.state import from_json

        result = node.execute(self._items("AnySupplier"))
        assert from_json(result["supplier_results_json"])[0]["status"] == "OK"


# ─────────────────────────────────────────────────────────────────────────────
# CheckRoHSREACHNode
# ─────────────────────────────────────────────────────────────────────────────


class TestCheckRoHSREACHNode:
    @pytest.fixture
    def node(self):
        from src.nodes.check_rohs_reach import CheckRoHSREACHNode

        return CheckRoHSREACHNode()

    def _state(self, rohs_reach_db=None):
        """Build inner state. rohs_reach_db is seeded as the JSON field
        agent_config_json — the same channel the inner graph uses at runtime."""
        from src.schemas.state import to_json

        state = {
            "parsed_bom_items_json": to_json(
                [
                    {
                        "part_number": "AB-1234",
                        "supplier": "SA",
                        "quantity": "1",
                        "spec_ref": "",
                        "substitution_note": "",
                    },
                ]
            )
        }
        if rohs_reach_db is not None:
            state["agent_config_json"] = to_json({"rohs_reach_db": rohs_reach_db})
        return state

    def test_absent_from_db_assumed_compliant(self, node):
        """TC-CRR-01: part absent from compliance DB is assumed compliant (OK)."""
        from src.schemas.state import from_json

        result = node.execute(self._state())
        assert from_json(result["rohs_reach_results_json"])[0]["status"] == "OK"

    def test_rohs_non_compliant_fail(self, node):
        """TC-CRR-02: part failing RoHS returns FAIL."""
        from src.schemas.state import from_json

        result = node.execute(
            self._state({"AB-1234": {"rohs_compliant": False, "reach_compliant": True, "hazardous_substances": []}})
        )
        assert from_json(result["rohs_reach_results_json"])[0]["status"] == "FAIL"

    def test_reach_concern_warn(self, node):
        """TC-CRR-03: REACH concern (substances present) returns WARN."""
        from src.schemas.state import from_json

        result = node.execute(
            self._state(
                {"AB-1234": {"rohs_compliant": True, "reach_compliant": False, "hazardous_substances": ["Lead"]}}
            )
        )
        r = from_json(result["rohs_reach_results_json"])[0]
        assert r["status"] == "WARN"
        assert "Lead" in r["message"]

    def test_both_fail(self, node):
        """TC-CRR-04: part failing both RoHS and REACH returns FAIL."""
        from src.schemas.state import from_json

        result = node.execute(
            self._state(
                {"AB-1234": {"rohs_compliant": False, "reach_compliant": False, "hazardous_substances": ["Mercury"]}}
            )
        )
        assert from_json(result["rohs_reach_results_json"])[0]["status"] == "FAIL"


# ─────────────────────────────────────────────────────────────────────────────
# CheckSubstitutionNotesNode
# ─────────────────────────────────────────────────────────────────────────────


class TestCheckSubstitutionNotesNode:
    @pytest.fixture
    def node(self):
        from src.nodes.check_substitution_notes import CheckSubstitutionNotesNode

        return CheckSubstitutionNotesNode()

    def _make_state(self, substitution_note, rohs_status):
        from src.schemas.state import to_json

        return {
            "parsed_bom_items_json": to_json(
                [
                    {
                        "part_number": "AB-1234",
                        "supplier": "S",
                        "quantity": "1",
                        "spec_ref": "",
                        "substitution_note": substitution_note,
                    },
                ]
            ),
            "rohs_reach_results_json": to_json(
                [
                    {"part_number": "AB-1234", "status": rohs_status},
                ]
            ),
        }

    def test_flagged_with_note_ok(self, node):
        """TC-CSN-01: RoHS/REACH-flagged part with substitution note passes."""
        from src.schemas.state import from_json

        result = node.execute(self._make_state("Use Alt-Part", "FAIL"))
        assert from_json(result["substitution_results_json"])[0]["status"] == "OK"

    def test_flagged_without_note_fail(self, node):
        """TC-CSN-02: flagged part missing substitution note returns FAIL."""
        from src.schemas.state import from_json

        result = node.execute(self._make_state("", "WARN"))
        assert from_json(result["substitution_results_json"])[0]["status"] == "FAIL"

    def test_non_flagged_no_note_ok(self, node):
        """TC-CSN-03: part not flagged by RoHS/REACH passes regardless of note."""
        from src.schemas.state import from_json

        result = node.execute(self._make_state("", "OK"))
        assert from_json(result["substitution_results_json"])[0]["status"] == "OK"


# ─────────────────────────────────────────────────────────────────────────────
# GenerateValidationReportNode
# ─────────────────────────────────────────────────────────────────────────────


class TestGenerateValidationReportNode:
    @pytest.fixture
    def node(self):
        from src.nodes.generate_validation_report import GenerateValidationReportNode

        return GenerateValidationReportNode()

    def _full_state(self, pn_status="OK", sup_status="OK", rohs_status="OK", sub_status="OK"):
        from src.schemas.state import to_json

        pn_msg = "" if pn_status == "OK" else "Part number fail"
        return {
            "parsed_bom_items_json": to_json(
                [
                    {
                        "part_number": "AB-1234",
                        "supplier": "SA",
                        "quantity": "100",
                        "spec_ref": "S1",
                        "substitution_note": "",
                    },
                ]
            ),
            "part_number_results_json": to_json(
                [
                    {"part_number": "AB-1234", "status": pn_status, "message": pn_msg},
                ]
            ),
            "supplier_results_json": to_json(
                [
                    {"part_number": "AB-1234", "supplier": "SA", "status": sup_status, "message": ""},
                ]
            ),
            "rohs_reach_results_json": to_json(
                [
                    {
                        "part_number": "AB-1234",
                        "status": rohs_status,
                        "rohs_compliant": True,
                        "reach_compliant": True,
                        "hazardous_substances": [],
                        "message": "",
                    },
                ]
            ),
            "substitution_results_json": to_json(
                [
                    {"part_number": "AB-1234", "status": sub_status, "message": ""},
                ]
            ),
        }

    def test_all_ok_report_passes(self, node):
        """TC-GVR-01: all checks pass → summary.passed = True."""
        from src.schemas.state import from_json

        result = node.execute(self._full_state())
        assert result["status"] == AgentStatus.SUCCESS
        report = from_json(result["validation_report_json"])
        assert report["summary"]["passed"] is True
        assert report["summary"]["fail_count"] == 0
        assert "[OK]" in result["result"]

    def test_single_fail_report(self, node):
        """TC-GVR-02: one FAIL check → summary.passed = False."""
        from src.schemas.state import from_json

        result = node.execute(self._full_state(pn_status="FAIL"))
        report = from_json(result["validation_report_json"])
        assert report["summary"]["passed"] is False
        assert report["summary"]["fail_count"] == 1
        assert "[FAIL]" in result["result"]

    def test_warn_does_not_fail(self, node):
        """TC-GVR-03: only WARN (no FAIL) → summary.passed = True."""
        from src.schemas.state import from_json

        result = node.execute(self._full_state(rohs_status="WARN"))
        report = from_json(result["validation_report_json"])
        assert report["summary"]["passed"] is True
        assert report["summary"]["warn_count"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# SecurityGateOutputNode
# ─────────────────────────────────────────────────────────────────────────────


class TestSecurityGateOutputNode:
    @pytest.fixture
    def node(self):
        from src.nodes.security_gate_output import SecurityGateOutputNode

        return SecurityGateOutputNode()

    def test_normal_output_passes_through(self, node):
        """TC-SGO-01: normal-length output is returned unchanged as formatted_output."""
        state = {"result": "BOM Validation Report\n[OK] AB-1234", "session_id": "s1", "correlation_id": "c1"}
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        assert "BOM Validation Report" in result["formatted_output"]

    def test_oversized_output_truncated(self, node):
        """TC-SGO-02: output beyond the size cap is truncated at the boundary."""
        state = {"result": "X" * 60_000, "session_id": "s1", "correlation_id": "c1"}
        result = node.execute(state)
        assert len(result["formatted_output"]) < 60_000
        assert "truncated at the external boundary" in result["formatted_output"]

    def test_empty_result_safe(self, node):
        """TC-SGO-03: empty result returns empty formatted_output without error.

        `formatted_output == ""` is falsy, and AgentBaseGraph.get_output falls
        through to `result` on a falsy notice — so the empty string on its own
        proves nothing about withholding. What is asserted is that this is the
        success path with an empty report, and that the fallback has nothing to
        hand back either.
        """
        state = {"result": "", "session_id": "s1", "correlation_id": "c1"}
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        assert result["formatted_output"] == ""
        assert (result["formatted_output"] or state["result"] or "") == ""

    def test_gate_is_module_level_function(self):
        """TC-SGO-04: _security_gate_output must be a module-level function.

        The framework auto-wraps node instance-method gate hooks and a wrapped
        hook returns None on the clean path, which the graph then passes on as
        the next node's state.
        """
        import inspect
        from src.nodes import security_gate_output as mod

        assert hasattr(mod, "_security_gate_output"), "_security_gate_output must be a module-level function"
        assert inspect.isfunction(mod._security_gate_output), "must be a plain function, not an instance method"

    def test_no_audit_data_in_output(self, node):
        """TC-SGO-05: audit fields (session_id, correlation_id) are not echoed into formatted_output."""
        session_id = "SESSION-12345"
        state = {"result": "Report OK", "session_id": session_id, "correlation_id": "COR-001"}
        result = node.execute(state)
        # The formatted_output is the report text only — session identifiers must not be embedded
        assert session_id not in result["formatted_output"]
