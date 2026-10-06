"""AgentCore Platform v1.0"""

# AgentRegistry entry point.
#
# config/agent.yaml declares:
#   module: "src.graph"
#   class:  "ManufacturingBOMValidationAgent"
#
# AgentRegistry resolves that pair with
# getattr(import_module("src.graph"), "ManufacturingBOMValidationAgent"),
# so the package __init__ must re-export the class from the graph module.
# Without this re-export the manifest entry point raises AttributeError at
# registry load time even though CI (which imports src.graph.graph directly)
# stays green.

from .graph import ManufacturingBOMValidationAgent

__all__ = ["ManufacturingBOMValidationAgent"]
