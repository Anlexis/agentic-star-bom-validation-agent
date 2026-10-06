# Invoke-order boundary: a full agent.invoke() must execute the fixed
# AgentBaseGraph backbone in order.
#
# The Cat 2 backbone is fixed and is NEVER overridden by a Cat 2 template
# (add_edges() belongs to the framework):
#
#     START -> initialize -> pre_process -> main -> {route} -> post_process
#           -> finalize -> END
#
# The framework records every executed node in `node_history` (an AgentState
# field whose reducer is operator.add, so entries accumulate in execution
# order). Each entry is the node's CLASS NAME - appended by BaseNode.__call__.
#
# For MFG-C2-012 (Cat 2, two-layer nested) the `main` slot is a GraphNode
# subclass (BOMValidationGraphNode) that delegates to the inner
# BOMValidationWorkflowGraph. The inner graph runs with its own state; its
# inner node_history is NOT merged back into the outer state (merge_output()
# maps only result / status), so the OUTER node_history contains exactly the
# five backbone slots - never the inner domain nodes.
#
# This test drives a real end-to-end Graph().invoke() over a valid domain
# payload and asserts the surfaced node_history matches the canonical backbone
# order. A SUCCESS terminal status is required: on any non-SUCCESS status
# route() short-circuits main -> finalize and the post_process slot is
# skipped, which is itself an invoke-order violation this test would catch.
#
# Deterministic - no model, no network. framework.* / src.* imports only.

import json

from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.graph.graph import ManufacturingBOMValidationAgent


# --- TEMPLATE-SPECIFIC ------------------------------------------------------
# The `main`-slot GraphNode class name for THIS template. A sibling template
# mirroring this canonical changes ONLY this one entry (its own domain
# <...>GraphNode); the other four backbone slot names are fixed by the
# framework and identical across every Cat 1 / Cat 2 template.
_MAIN_SLOT_NODE = "BOMValidationGraphNode"

# A valid, PII-free BOM payload that drives the full domain workflow to a
# SUCCESS terminal status. The user_input is a JSON object that includes the
# BOM content so the full pipeline (parse → validate → report) succeeds.
# Shape: {"bom_content": <csv text>, "bom_format": "csv"} — mirrors the
# fallback path in ValidateInputNode (JSON embedded in user_input) which is
# used when input_context is not provided at invoke() time.
_VALID_PAYLOAD = json.dumps(
    {
        "bom_content": (
            "part_number,supplier,quantity,spec_ref,substitution_note\n"
            "AB-1234,SupplierA,100,SPEC-001,\n"
            "CD-5678,SupplierB,50,SPEC-002,Use alt variant\n"
        ),
        "bom_format": "csv",
    }
)
# --- END TEMPLATE-SPECIFIC --------------------------------------------------

# Canonical AgentBaseGraph backbone execution order, by node class name as
# recorded in node_history. Four entries are fixed by the framework and
# identical for every template; only _MAIN_SLOT_NODE is template-specific.
_EXPECTED_ORDER = [
    "InitializeNode",  # framework default  (initialize slot)
    "ValidateInputNode",  # domain pre_process (caller-data contract)
    _MAIN_SLOT_NODE,  # TEMPLATE-SPECIFIC  (main slot GraphNode)
    "SecurityGateOutputNode",  # domain post_process (output boundary)
    "FinalizeNode",  # framework default  (finalize slot)
]


def _run() -> dict:
    """Run a full end-to-end invocation as a real external caller and return the output.

    Uses InvocationContext(caller_trust_level=TrustLevel.VERIFIED_EXTERNAL) — the
    trust level a real external caller arrives on. The backbone trust gate
    (pre_process ValidateInputNode requires VERIFIED_EXTERNAL) admits it, and
    GraphNode.execute() passes this context UNCHANGED into the inner
    BOMValidationWorkflowGraph, whose domain nodes declare TrustLevel.ANONYMOUS
    (0 <= any caller) — so the inner trust gate admits it too and post_process runs.
    An INTERNAL / for_internal() context would mask an inner-node INTERNAL trap that
    only bites the real external path (INTERNAL > VERIFIED_EXTERNAL → the inner gate denies).
    """
    ctx = InvocationContext(caller_trust_level=TrustLevel.VERIFIED_EXTERNAL, caller_id="test-suite")
    return ManufacturingBOMValidationAgent().invoke(_VALID_PAYLOAD, ctx=ctx)


class TestInvokeOrderBoundary:
    """PB-6: full agent.invoke() executes the backbone in the fixed order."""

    def test_invoke_reaches_success(self):
        """The full run must terminate SUCCESS - otherwise route() short-circuits
        main -> finalize and the post_process slot never runs."""
        result = _run()
        assert (
            result.get("status") == AgentStatus.SUCCESS.value
        ), f"Expected SUCCESS, got {result.get('status')!r}. result={result!r}"

    def test_output_is_non_empty(self):
        """A successful run must surface a non-empty gated output."""
        assert _run().get("output"), "invoke() surfaced an empty output"

    def test_node_history_is_populated(self):
        """node_history must be a non-empty list of node class-name strings."""
        history = _run().get("node_history")
        assert isinstance(history, list) and history, f"node_history must be a non-empty list, got {history!r}"
        assert all(isinstance(n, str) for n in history), f"node_history entries must be strings, got {history!r}"

    def test_backbone_slot_order(self):
        """Core invoke-order boundary: the pre_process slot runs before the
        domain main slot, which runs before the post_process slot - as a
        strict ordered subsequence of node_history."""
        history = _run().get("node_history", [])
        ordered_slots = ["ValidateInputNode", _MAIN_SLOT_NODE, "SecurityGateOutputNode"]
        for name in ordered_slots:
            assert name in history, f"Expected backbone slot {name!r} in node_history, got {history!r}"
        positions = [history.index(name) for name in ordered_slots]
        assert positions == sorted(positions), (
            f"Backbone slots executed out of order: {ordered_slots} at {positions}. " f"node_history={history!r}"
        )

    def test_full_backbone_sequence(self):
        """The complete AgentBaseGraph backbone order:
        initialize -> pre_process -> main -> post_process -> finalize."""
        history = _run().get("node_history", [])
        assert history == _EXPECTED_ORDER, (
            "node_history does not match the canonical backbone order.\n"
            f"  expected: {_EXPECTED_ORDER}\n"
            f"  actual:   {history}"
        )
