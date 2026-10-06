"""AgentCore Platform v1.0"""

# src/graph/context_bridge.py — carries the caller's input_context across the
# outer→inner graph boundary.
#
# Why this exists: GraphNode.execute() invokes the inner graph as
# `subgraph.invoke(user_input, session_id=..., ctx=...)` without forwarding the
# outer state's input_context, so an inner-node read of state["input_context"]
# would always see {} through the full nested graph. The sanctioned subclass
# hooks bridge it:
#
#   BOMValidationGraphNode.extract_input(state)   [runs BEFORE subgraph.invoke]
#       → set_caller_input_context(...)
#   BOMValidationWorkflowGraph._extra_initial_state()  [runs INSIDE subgraph.invoke]
#       → returns {"input_context": get_caller_input_context()}
#
# A ContextVar keeps the hand-off correct per thread/task, so concurrent
# invocations in one process cannot see each other's context.
#
# The BOM record travels on this channel rather than inside user_input for a
# second, load-bearing reason: the framework input gate masks detected personal
# names in user_input, and a two-word supplier or component label
# ("Nippon Bearing", "Main Rotor Assembly") has exactly that shape. Routed
# through user_input the report names [MASKED] instead of the real supplier,
# and the Approved-Supplier-List comparison is made against the mask. The
# context channel is not name-masked — which is why ValidateInputNode screens
# it directly for contact identifiers instead of relying on that gate.

from contextvars import ContextVar
from typing import Any

_CALLER_INPUT_CONTEXT: ContextVar[dict[str, Any] | None] = ContextVar("mfg_c2_012_caller_input_context", default=None)


def set_caller_input_context(input_context: dict[str, Any] | None) -> None:
    """Stash the outer graph's input_context for the imminent inner-graph invoke."""
    _CALLER_INPUT_CONTEXT.set(dict(input_context) if input_context else {})


def get_caller_input_context() -> dict[str, Any]:
    """Read (without consuming) the stashed input_context; {} when none was set."""
    return _CALLER_INPUT_CONTEXT.get() or {}
