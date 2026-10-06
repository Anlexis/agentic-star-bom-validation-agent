"""MFG-C2-012 — Unit tests: the caller trust gate.

Every invocation here goes through `node(state)` — BaseNode.__call__ — which runs
the trust gate -> the framework input gate -> execute() -> the framework output
gate. Calling `node.execute(state)` directly skips __call__ entirely, so the trust
gate never runs and a "trust" test written that way asserts nothing.

Contract exercised:
  - A denial RETURNS an error dict (it never raises): status ERROR plus
    "trust gate denied" in error_log.
  - execute() does not run on a denial, so every key that only execute() writes is
    ABSENT from the returned dict. The assertions below are keyed on the output of
    the node under test specifically (ValidateInputNode writes validated_input /
    bom_content / bom_format), not on a bare status check that some other gate in
    the pipeline could satisfy.
"""

import json

import pytest

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.nodes.check_approved_suppliers import CheckApprovedSuppliersNode
from src.nodes.check_rohs_reach import CheckRoHSREACHNode
from src.nodes.check_substitution_notes import CheckSubstitutionNotesNode
from src.nodes.generate_validation_report import GenerateValidationReportNode
from src.nodes.parse_bom_file import ParseBOMFileNode
from src.nodes.security_gate_output import SecurityGateOutputNode
from src.nodes.validate_input import ValidateInputNode
from src.nodes.validate_part_numbers import ValidatePartNumbersNode

CSV_BOM_CONTENT = (
    "part_number,supplier,quantity,spec_ref,substitution_note\n"
    "AB-1234,SupplierA,100,SPEC-001,\n"
    "CD-5678,SupplierB,50,SPEC-002,Use RoHS-compliant variant\n"
)


@pytest.fixture(autouse=True)
def _patch_all_emit(monkeypatch):
    """Silence emit_trace_event in the node modules under test (never via sys.modules)."""

    def noop(*args, **kwargs):
        return None

    for mod in (
        "src.nodes.validate_input",
        "src.nodes.parse_bom_file",
        "src.nodes.security_gate_output",
    ):
        monkeypatch.setattr(mod + ".emit_trace_event", noop, raising=False)


def _state(trust_value: str, **extra) -> dict:
    """Outer-graph state carrying an explicit caller trust level."""
    state = {
        "user_input": "Validate BOM",
        "input_context": {"bom_content": CSV_BOM_CONTENT, "bom_format": "csv"},
        "caller_trust_level": trust_value,
        "node_history": [],
        "error_log": [],
        "session_id": "test-session",
        "execution_time": {},
    }
    state.update(extra)
    return state


class TestTrustGate:
    """Trust enforcement on the VERIFIED_EXTERNAL pre_process slot."""

    def test_anonymous_caller_denied_on_validate_input(self):
        """ANONYMOUS caller on the VERIFIED_EXTERNAL ValidateInputNode is denied.

        __call__ must RETURN the error dict rather than raise, and none of
        ValidateInputNode's own outputs may appear — execute() never ran.
        """
        node = ValidateInputNode()  # required_trust_level = VERIFIED_EXTERNAL
        result = node(_state(TrustLevel.ANONYMOUS.value))

        assert result.get("status") == AgentStatus.ERROR.value
        error_log = result.get("error_log", [])
        assert any(
            "trust gate denied" in str(e) for e in error_log
        ), f"Expected 'trust gate denied' in error_log, got: {error_log}"
        # ValidateInputNode's own execute() output — must be absent on a denial.
        assert "validated_input" not in result, "a denial leaked validated_input"
        assert "bom_content" not in result, "a denial leaked bom_content"
        assert "bom_format" not in result, "a denial leaked bom_format"

    def test_verified_external_caller_passes_validate_input(self):
        """VERIFIED_EXTERNAL caller clears the gate and ValidateInputNode runs.

        This is the positive control for the denial test above: the same node and
        the same state, differing only in caller trust, produces this node's own
        sanitised output.
        """
        node = ValidateInputNode()
        result = node(_state(TrustLevel.VERIFIED_EXTERNAL.value))

        assert result.get("status") == AgentStatus.SUCCESS.value
        assert result.get("validated_input") == "Validate BOM"
        assert result.get("bom_content") == CSV_BOM_CONTENT
        assert result.get("bom_format") == "csv"

    def test_gate_runs_before_node_input_validation(self):
        """An ANONYMOUS caller is refused before ValidateInputNode's own checks.

        The payload here would fail the node's own construct screen if execute()
        ran, so a "trust gate denied" verdict proves the trust gate fired first.
        """
        node = ValidateInputNode()
        malicious = "part_number,supplier\n<script>alert(1)</script>,BadSupplier"
        result = node(
            _state(
                TrustLevel.ANONYMOUS.value,
                input_context={"bom_content": malicious, "bom_format": "csv"},
            )
        )
        assert result.get("status") == AgentStatus.ERROR.value
        assert any("trust gate denied" in str(e) for e in result.get("error_log", []))
        assert not any(
            "disallowed construct" in str(e) for e in result.get("error_log", [])
        ), "execute() ran despite the trust denial"

    def test_verified_external_caller_rejected_on_empty_input(self):
        """Gate passes, then ValidateInputNode's own validation rejects empty input."""
        node = ValidateInputNode()
        result = node(_state(TrustLevel.VERIFIED_EXTERNAL.value, user_input=""))
        assert result.get("status") == AgentStatus.SUCCESS.value
        assert any("empty" in str(e) for e in result.get("error_log", []))
        assert not any(
            "trust gate denied" in str(e) for e in result.get("error_log", [])
        ), "a VERIFIED_EXTERNAL caller must clear the trust gate"

    def test_anonymous_caller_allowed_on_inner_node(self):
        """An ANONYMOUS inner domain node admits an ANONYMOUS caller and runs."""
        node = ParseBOMFileNode()  # required_trust_level = ANONYMOUS
        result = node(
            {
                "user_input": json.dumps({"bom_content": CSV_BOM_CONTENT, "bom_format": "csv"}),
                "caller_trust_level": TrustLevel.ANONYMOUS.value,
                "node_history": [],
                "error_log": [],
                "execution_time": {},
            }
        )
        assert result.get("status") == AgentStatus.SUCCESS.value
        assert result.get("parsed_bom_items_json"), "inner node should produce parsed BOM line items"
        assert not any("trust gate denied" in str(e) for e in result.get("error_log", []))

    def test_anonymous_caller_allowed_on_output_gate(self):
        """The post_process output-gate node is ANONYMOUS and produces its own output."""
        node = SecurityGateOutputNode()
        result = node(
            {
                "result": "=== BOM Validation Report ===\nOverall: PASS",
                "caller_trust_level": TrustLevel.ANONYMOUS.value,
                "session_id": "s1",
                "correlation_id": "c1",
                "node_history": [],
                "error_log": [],
                "execution_time": {},
            }
        )
        assert result.get("status") == AgentStatus.SUCCESS.value
        assert "BOM Validation Report" in result.get("formatted_output", "")


class TestTrustLevelMatrix:
    """The template's declared trust matrix (docs/02_design.md).

    The outer pre_process slot is the external boundary and requires
    VERIFIED_EXTERNAL; the post_process gate and the six inner domain nodes run
    behind that boundary and are declared ANONYMOUS per the Cat-2 nested convention.
    """

    def test_pre_process_slot_requires_verified_external(self):
        assert ValidateInputNode.required_trust_level is TrustLevel.VERIFIED_EXTERNAL

    def test_inner_and_output_nodes_admit_anonymous(self):
        for node_cls in (
            SecurityGateOutputNode,
            ParseBOMFileNode,
            ValidatePartNumbersNode,
            CheckApprovedSuppliersNode,
            CheckRoHSREACHNode,
            CheckSubstitutionNotesNode,
            GenerateValidationReportNode,
        ):
            assert node_cls.required_trust_level is TrustLevel.ANONYMOUS, (
                f"{node_cls.__name__} must declare TrustLevel.ANONYMOUS "
                "(inner Cat-2 domain node / post-boundary output gate)"
            )
