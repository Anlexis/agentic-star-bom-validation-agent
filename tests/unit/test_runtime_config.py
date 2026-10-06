"""MFG-C2-012 — declared runtime configuration actually reaches the code.

A declared value that no reader consumes is worse than no declaration: the file
says the agent behaves one way and it behaves another, and nothing fails. These
tests check the whole path — file, validation, forwarding across the nested
graph boundary, and the verdict the domain node finally produces — rather than
checking that the key exists.
"""

import textwrap

import pytest
import yaml

from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.graph import graph as graph_module
from src.graph.graph import (
    BOMValidationGraphNode,
    ManufacturingBOMValidationAgent,
    _runtime_config,
    _validated_rules,
)

CSV_BOM = "part_number,supplier,quantity\nAB-1234,SupplierA,100\n"


def _write_config(tmp_path, mapping):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(mapping, sort_keys=False), encoding="utf-8")
    return path


class TestShippedConfiguration:
    """The file this repository ships is loadable and complete."""

    def test_runtime_config_loads(self):
        cfg = _runtime_config()
        assert isinstance(cfg, dict) and cfg, "config/config.yaml must load as a mapping"

    def test_backbone_parameters_are_declared(self):
        cfg = _runtime_config()
        assert cfg["max_retry"] == 3
        assert cfg["timeout_s"] == 30

    def test_every_declared_validation_rule_survives_validation(self):
        """A rule that fails validation is dropped, so a shipped rule that never
        arrives would be a silently dead declaration."""
        declared = set(_runtime_config().get("validation", {}))
        forwarded = set(_validated_rules(_runtime_config()))
        assert declared == forwarded, f"declared but not forwarded: {declared - forwarded}"

    def test_forwarded_block_is_what_the_graph_node_hands_the_inner_graph(self):
        forwarded = BOMValidationGraphNode()._parent_config()
        assert forwarded["configurable"] == _validated_rules(_runtime_config())
        assert forwarded["configurable"], "the inner graph must not be handed an empty config"


class TestRuleValidation:
    """Malformed declarations are dropped, never forwarded."""

    @pytest.mark.parametrize("pattern", ["[unclosed", "(?P<x>", "A" * 201, 7, None, ["^A$"]])
    def test_unusable_patterns_are_dropped(self, pattern):
        rules = _validated_rules({"validation": {"part_number_pattern": pattern}})
        assert "part_number_pattern" not in rules

    def test_usable_pattern_is_forwarded(self):
        rules = _validated_rules({"validation": {"part_number_pattern": r"^ZZ-\d{3}$"}})
        assert rules["part_number_pattern"] == r"^ZZ-\d{3}$"

    @pytest.mark.parametrize("asl", ["SupplierA", {"a": 1}, [1, 2], ["ok", 5], ["x" * 129]])
    def test_malformed_supplier_lists_are_dropped(self, asl):
        """A non-list would make the membership test behave as 'no list configured'
        — i.e. pass every supplier, which is the fail-open direction."""
        assert "approved_suppliers" not in _validated_rules({"validation": {"approved_suppliers": asl}})

    def test_valid_supplier_list_is_forwarded(self):
        rules = _validated_rules({"validation": {"approved_suppliers": ["SupplierA"]}})
        assert rules["approved_suppliers"] == ["SupplierA"]

    @pytest.mark.parametrize(
        "ceiling",
        [float("nan"), float("inf"), float("-inf"), "10", True, 0, -5, 50_001, 1.5, None],
    )
    def test_unusable_ceilings_are_dropped(self, ceiling):
        """A non-finite ceiling compares False against every bound, so an
        unchecked one silently disables the limit it exists to impose."""
        assert "max_line_items" not in _validated_rules({"validation": {"max_line_items": ceiling}})

    def test_valid_ceiling_is_forwarded(self):
        assert _validated_rules({"validation": {"max_line_items": 250}})["max_line_items"] == 250

    @pytest.mark.parametrize("block", [None, "text", 7, []])
    def test_a_malformed_block_degrades_to_no_rules(self, block):
        assert _validated_rules({"validation": block}) == {}

    def test_a_missing_file_degrades_to_no_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr(graph_module, "_RUNTIME_CONFIG_PATH", tmp_path / "absent.yaml")
        assert _runtime_config() == {}

    def test_unparseable_file_degrades_to_no_config(self, tmp_path, monkeypatch):
        path = tmp_path / "config.yaml"
        path.write_text("max_retry: [unclosed", encoding="utf-8")
        monkeypatch.setattr(graph_module, "_RUNTIME_CONFIG_PATH", path)
        assert _runtime_config() == {}


class TestDeclaredValuesReachTheGraph:
    """End to end: a value written in the file changes the verdict."""

    def _invoke(self):
        agent = ManufacturingBOMValidationAgent(config=_runtime_config())
        agent.compile()
        ctx = InvocationContext(session_id="config-test", caller_trust_level=TrustLevel.VERIFIED_EXTERNAL)
        return agent.invoke(
            "Validate BOM",
            ctx=ctx,
            input_context={"bom_content": CSV_BOM, "bom_format": "csv"},
        )

    def test_declared_part_number_rule_reaches_the_inner_domain_node(self, tmp_path, monkeypatch):
        """The rule crosses graph, node, boundary and state to change a verdict.

        AB-1234 passes the shipped rule and fails this one, so a report that
        still says OK proves the declaration never arrived.
        """
        monkeypatch.setattr(
            graph_module,
            "_RUNTIME_CONFIG_PATH",
            _write_config(tmp_path, {"validation": {"part_number_pattern": r"^ZZ-\d{3}$"}}),
        )
        output = self._invoke()
        assert output["status"] == AgentStatus.SUCCESS.value
        assert "does not match OEM format rule" in output["output"]

    def test_shipped_part_number_rule_accepts_the_same_part(self):
        """The control for the test above, on the configuration as shipped."""
        output = self._invoke()
        assert output["status"] == AgentStatus.SUCCESS.value
        assert "does not match OEM format rule" not in output["output"]

    def test_declared_supplier_list_reaches_the_inner_domain_node(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            graph_module,
            "_RUNTIME_CONFIG_PATH",
            _write_config(tmp_path, {"validation": {"approved_suppliers": ["OtherSupplier"]}}),
        )
        assert "Approved Supplier List" in self._invoke()["output"]

    def test_declared_line_item_ceiling_reaches_the_parser(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            graph_module,
            "_RUNTIME_CONFIG_PATH",
            _write_config(tmp_path, {"validation": {"max_line_items": 1}}),
        )
        many = "part_number,supplier,quantity\n" + "".join(f"AB-{1000 + i},SupplierA,1\n" for i in range(5))
        agent = ManufacturingBOMValidationAgent(config=_runtime_config())
        agent.compile()
        ctx = InvocationContext(session_id="ceiling-test", caller_trust_level=TrustLevel.VERIFIED_EXTERNAL)
        output = agent.invoke("Validate BOM", ctx=ctx, input_context={"bom_content": many, "bom_format": "csv"})
        assert "Total: 1 items" in output["output"]

    def test_declared_backbone_parameters_reach_the_outer_graph(self):
        """The outer graph must be constructed WITH the file, not with nothing.

        A graph built as Graph() carries an empty config, so every declared
        backbone parameter is dead while every test still passes.
        """
        agent = ManufacturingBOMValidationAgent(config=_runtime_config())
        assert agent.config.get("max_retry") == 3
        assert ManufacturingBOMValidationAgent().config.get("max_retry") is None

    def test_the_server_constructs_the_agent_with_the_declared_config(self):
        """The deployed entry point is the one that has to get this right."""
        source = textwrap.dedent(
            (graph_module.Path(__file__).resolve().parents[2] / "src/api/server.py").read_text(encoding="utf-8")
        )
        assert "ManufacturingBOMValidationAgent(config=_runtime_config())" in source
