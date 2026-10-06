"""MFG-C2-012 — the caller-data contract.

Everything the caller controls is checked in ValidateInputNode (the request
boundary) and ParseBOMFileNode (where caller text becomes report content).
These tests drive both directions of every screen: the hostile form is refused,
and an ordinary BOM carrying similar-looking text is not.

Every refusal here is asserted by calling ``execute()`` DIRECTLY, with no
framework wrapper in front. That is deliberate: the guarantee has to belong to
the template, so it must hold in a deployment whose platform gates are absent
or configured differently. Assertions are behavioural — error status, nothing
carried forward — never the wording of any gate.
"""

import json

import pytest

from framework.schemas.agent_status import AgentStatus

from src.nodes.parse_bom_file import ParseBOMFileNode
from src.nodes.validate_input import ValidateInputNode
from src.schemas.state import from_json

CSV_BOM = (
    "part_number,supplier,quantity,spec_ref,substitution_note\n"
    "AB-1234,SupplierA,100,SPEC-001,\n"
    "CD-5678,SupplierB,50,SPEC-002,Use alt variant\n"
)


@pytest.fixture(autouse=True)
def _silence_audit(monkeypatch):
    def noop(*args, **kwargs):
        return None

    for mod in ("src.nodes.validate_input", "src.nodes.parse_bom_file"):
        monkeypatch.setattr(mod + ".emit_trace_event", noop, raising=False)


def _state(**context):
    base = {"bom_content": CSV_BOM, "bom_format": "csv"}
    base.update(context)
    return {"user_input": "Validate BOM", "input_context": base}


def _assert_refused(result, *carried_keys, code="INVALID_REQUEST"):
    """A refusal names a field and carries nothing forward.

    `code` says which of the two refusal shapes is expected. A value the caller
    can correct completes the run carrying that reason code, so the request can
    be sent again; `code=None` is a refusal that terminates, which is reserved
    for what rewording cannot fix (a personal identifier in the document, an
    executable construct).
    """
    if code is None:
        assert result["status"] == AgentStatus.ERROR.value
        assert "error_code" not in result
    else:
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["error_code"] == code
    assert result.get("error_log"), "a refusal must record why"
    for key in carried_keys:
        assert key not in result, f"a refusal leaked {key}"


# ─────────────────────────────────────────────────────────────────────────────
# Caller-supplied numbers: finite, bounded, strictly typed, fail CLOSED
# ─────────────────────────────────────────────────────────────────────────────


class TestMaxLineItemsContract:
    """max_line_items is the caller-supplied number on the request channel."""

    @pytest.fixture
    def node(self):
        return ValidateInputNode()

    @pytest.mark.parametrize(
        "value",
        [
            float("nan"),
            float("inf"),
            float("-inf"),
            "NaN",
            "Infinity",
            "-Infinity",
            "100",  # a string is not an integer, however plausible it looks
            str(float("nan")),  # "nan" — coercion would accept this
            True,  # isinstance(True, int) is True in Python
            False,
            1.5,
            0,
            -1,
            5_001,
            10**12,
            None if False else [],  # a container is not a number
        ],
    )
    def test_non_finite_and_mistyped_values_are_refused(self, node, value):
        """Every non-finite, mistyped or out-of-range ceiling fails CLOSED.

        A NaN ceiling is the dangerous one: NaN comparisons are always False, so
        an unchecked NaN silently disables the bound it exists to enforce.
        """
        result = node.execute(_state(max_line_items=value))
        _assert_refused(result, "bom_content", "max_line_items")

    @pytest.mark.parametrize("value", [1, 10, 5_000])
    def test_valid_ceilings_are_accepted(self, node, value):
        """Positive control: an in-range integer ceiling is honoured."""
        result = node.execute(_state(max_line_items=value))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["max_line_items"] == value

    def test_absent_ceiling_is_allowed(self, node):
        """The field is optional — absence is not a rejection."""
        result = node.execute(_state())
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["max_line_items"] is None

    def test_rejection_does_not_echo_the_value(self, node):
        """The error names the field, never the submitted value."""
        result = node.execute(_state(max_line_items="9999999999999"))
        joined = " ".join(result["error_log"])
        assert "max_line_items" in joined
        assert "9999999999999" not in joined


class TestQuantityContract:
    """quantity is the caller-supplied number inside the document itself."""

    @pytest.fixture
    def node(self):
        return ParseBOMFileNode()

    @pytest.mark.parametrize(
        "raw",
        ["nan", "NaN", "inf", "Infinity", "-1", "1.5", "1e5", "0x10", "True", "  ", "1_000", "1000000001"],
    )
    def test_non_integer_quantities_fail_the_document(self, node, raw):
        """A quantity is a run of digits or it is not a quantity.

        str(float("nan")) is the string "nan", which passes any shape check
        loose enough to accept a number written as text — so the column is
        typed, not coerced.
        """
        content = f"part_number,supplier,quantity\nAB-1234,SupplierA,{raw}\n"
        result = node.execute({"bom_content": content, "bom_format": "csv"})
        if raw.strip() == "":
            # An absent quantity is allowed; it renders as unknown.
            assert result["status"] == AgentStatus.SUCCESS.value
            return
        _assert_refused(result, "parsed_bom_items_json")
        assert "quantity" in " ".join(result["error_log"])

    def test_valid_quantity_is_typed_as_an_integer(self, node):
        result = node.execute({"bom_content": CSV_BOM, "bom_format": "csv"})
        items = from_json(result["parsed_bom_items_json"])
        assert [i["quantity"] for i in items] == [100, 50]

    def test_absent_quantity_is_allowed(self, node):
        content = "part_number,supplier,quantity\nAB-1234,SupplierA,\n"
        result = node.execute({"bom_content": content, "bom_format": "csv"})
        assert result["status"] == AgentStatus.SUCCESS.value
        assert from_json(result["parsed_bom_items_json"])[0]["quantity"] is None


# ─────────────────────────────────────────────────────────────────────────────
# Caller strings that render into the report
# ─────────────────────────────────────────────────────────────────────────────


class TestRenderedFieldAlphabets:
    """Every caller string reaching the report is confined to a bounded alphabet."""

    @pytest.fixture
    def node(self):
        return ParseBOMFileNode()

    @pytest.mark.parametrize(
        "part_number",
        ["<b>AB-1234</b>", "AB;1234", "AB{1234}", "AB`1234`", "A" * 65, "AB 1234"],
    )
    def test_out_of_alphabet_part_numbers_fail_the_document(self, node, part_number):
        content = f"part_number,supplier,quantity\n{part_number},SupplierA,10\n"
        result = node.execute({"bom_content": content, "bom_format": "csv"})
        _assert_refused(result, "parsed_bom_items_json")
        assert "part_number" in " ".join(result["error_log"])

    @pytest.mark.parametrize(
        "part_number",
        ["AB-1234", "SKF-6205-2RS", "EAB64785603", "48210", "ABCD-12345678-R1", "FLT/AIR-330", "HYD200BAR", "M8X1.25"],
    )
    def test_real_manufacturing_identifiers_are_accepted(self, node, part_number):
        """Positive control: the identifiers this domain actually renders pass."""
        content = f"part_number,supplier,quantity\n{part_number},SupplierA,10\n"
        result = node.execute({"bom_content": content, "bom_format": "csv"})
        assert result["status"] == AgentStatus.SUCCESS.value
        assert from_json(result["parsed_bom_items_json"])[0]["part_number"] == part_number

    @pytest.mark.parametrize(
        "supplier",
        ["Panasonic Parts", "Nippon Bearing", "SKF (Japan)", "Denso Corporation", "Yamada & Co.", "Sumitomo-Riko"],
    )
    def test_real_supplier_names_are_accepted(self, node, supplier):
        content = f"part_number,supplier,quantity\nAB-1234,{supplier},10\n"
        result = node.execute({"bom_content": content, "bom_format": "csv"})
        assert result["status"] == AgentStatus.SUCCESS.value
        assert from_json(result["parsed_bom_items_json"])[0]["supplier"] == supplier

    @pytest.mark.parametrize("supplier", ["<script>x</script>", "S" * 129, "Supplier|Injected"])
    def test_out_of_alphabet_supplier_names_fail_the_document(self, node, supplier):
        content = f"part_number,supplier,quantity\nAB-1234,{supplier},10\n"
        result = node.execute({"bom_content": content, "bom_format": "csv"})
        _assert_refused(result, "parsed_bom_items_json")

    def test_embedded_newline_in_a_quoted_field_fails_the_document(self, node):
        """A quoted field may legally carry a newline; the report may not.

        The report is line-oriented, so a supplier name containing a line break
        would let caller text forge an extra report line.
        """
        content = 'part_number,supplier,quantity\nAB-1234,"Supplier\nInjected",10\n'
        result = node.execute({"bom_content": content, "bom_format": "csv"})
        _assert_refused(result, "parsed_bom_items_json")


# ─────────────────────────────────────────────────────────────────────────────
# Contact identifiers: refused, never masked
# ─────────────────────────────────────────────────────────────────────────────


class TestContactIdentifierScreen:
    """The request channel is screened by the template, not by a platform gate.

    The framework masks personal names in the request STRING only, so a record
    delivered on the structured channel is not screened by it at all. The
    template screens that channel itself — and refuses rather than masks,
    because a BOM whose supplier labels had been silently rewritten still reads
    as an authoritative report.
    """

    @pytest.fixture
    def node(self):
        return ValidateInputNode()

    def test_email_in_the_document_is_refused(self, node):
        content = (
            "part_number,supplier,substitution_note\n" "AB-1234,SupplierA,contact buyer@example.com for approval\n"
        )
        result = node.execute(_state(bom_content=content))
        _assert_refused(result, "bom_content", code=None)

    def test_labelled_japanese_name_is_refused(self, node):
        content = "part_number,supplier,substitution_note\nAB-1234,SupplierA,担当者: 山田太郎\n"
        result = node.execute(_state(bom_content=content))
        _assert_refused(result, "bom_content", code=None)

    def test_component_labels_are_not_treated_as_personal_data(self, node):
        """The negative control, and the one that matters operationally.

        The framework's name heuristic matches any two consecutive capitalised
        words, which is the shape of a supplier or component label. Refusing on
        that class would refuse ordinary BOMs, so it is excluded and the labels
        survive byte-identical.
        """
        content = (
            "part_number,supplier,substitution_note\n"
            "AB-1234,Panasonic Parts,Main Rotor Assembly replacement approved\n"
        )
        result = node.execute(_state(bom_content=content))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["bom_content"] == content

    def test_grouped_digit_part_codes_are_not_treated_as_contact_data(self, node):
        """Digit-shaped contact classes are screened per field, not over the document.

        A part code written as grouped digit runs has the same shape as a card
        or national identifier; screening those classes over the raw document
        would refuse a legitimate BOM.
        """
        content = "part_number,supplier,quantity\n1234-5678-9012,SupplierA,10\n"
        result = node.execute(_state(bom_content=content))
        assert result["status"] == AgentStatus.SUCCESS.value

    def test_phone_number_in_a_free_text_column_fails_the_document(self):
        """Per field, where a digit run is unambiguously not an identifier."""
        node = ParseBOMFileNode()
        content = "part_number,supplier,substitution_note\n" "AB-1234,SupplierA,call 03-1234-5678 before substituting\n"
        result = node.execute({"bom_content": content, "bom_format": "csv"})
        _assert_refused(result, "parsed_bom_items_json", code=None)


# ─────────────────────────────────────────────────────────────────────────────
# Executable and markup constructs
# ─────────────────────────────────────────────────────────────────────────────


class TestDisallowedConstructScreen:
    @pytest.fixture
    def node(self):
        return ValidateInputNode()

    @pytest.mark.parametrize(
        "content",
        [
            "part_number,supplier\n<script>alert(1)</script>,S\n",
            "part_number,supplier\nAB-1234,<?php echo 1; ?>\n",
            "part_number,supplier\nAB-1234,eval(open('/etc/passwd'))\n",
            "part_number,supplier\nAB-1234,__import__('os')\n",
            '<!DOCTYPE bom [<!ENTITY x "y">]><bom><item><part_number>AB-1234</part_number></item></bom>',
        ],
    )
    def test_executable_constructs_are_refused(self, node, content):
        fmt = "xml" if content.startswith("<!DOCTYPE") else "csv"
        result = node.execute(_state(bom_content=content, bom_format=fmt))
        _assert_refused(result, "bom_content", code=None)

    @pytest.mark.parametrize(
        "note",
        [
            "Evaluate the alternative part before substitution",
            "System replacement scheduled for Q3",
            "Executive approval required",
            "Compile the compliance dossier",
            "Import duty applies to this component",
        ],
    )
    def test_ordinary_engineering_prose_is_not_refused(self, node, note):
        """The screen requires the construct's real syntax, not a bare keyword.

        A screen that fires on ordinary domain text blocks real work, which is
        the failure mode that actually costs a user something.
        """
        content = f"part_number,supplier,substitution_note\nAB-1234,SupplierA,{note}\n"
        result = node.execute(_state(bom_content=content))
        assert result["status"] == AgentStatus.SUCCESS.value


# ─────────────────────────────────────────────────────────────────────────────
# Channel integrity and structural bounds
# ─────────────────────────────────────────────────────────────────────────────


class TestChannelAndBounds:
    @pytest.fixture
    def node(self):
        return ValidateInputNode()

    def test_document_altered_in_transit_is_refused(self, node):
        """A BOM that arrived masked on the request-string channel is refused.

        The framework rewrites detected personal names in the request string
        before this node runs, and a two-word supplier label has that shape.
        Validating a document whose supplier names were rewritten would produce
        Approved-Supplier-List verdicts about names nobody submitted, so the
        node fails closed and points the caller at the structured channel.
        """
        altered = "part_number,supplier,quantity\nAB-1234,[MASKED],100\n"
        result = node.execute(
            {
                "user_input": json.dumps({"bom_content": altered, "bom_format": "csv"}),
                "input_context": {},
            }
        )
        _assert_refused(result, "bom_content")

    def test_structured_channel_is_preferred_over_the_request_string(self, node):
        """When both channels carry a record, the structured one wins."""
        other = "part_number,supplier,quantity\nZZ-9999,SupplierZ,1\n"
        result = node.execute(
            {
                "user_input": json.dumps({"bom_content": other, "bom_format": "csv"}),
                "input_context": {"bom_content": CSV_BOM, "bom_format": "csv"},
            }
        )
        assert result["bom_content"] == CSV_BOM

    @pytest.mark.parametrize("fmt", ["xlsx", "pdf", "CSV ", 7, ["csv"]])
    def test_unsupported_document_formats_are_refused(self, node, fmt):
        result = node.execute(_state(bom_format=fmt))
        if fmt == "CSV ":  # whitespace and case are normalised, not rejected
            assert result["status"] == AgentStatus.SUCCESS.value
            return
        _assert_refused(result, "bom_content")

    def test_format_rejection_does_not_echo_the_value(self, node):
        result = node.execute(_state(bom_format="xlsx"))
        assert "xlsx" not in " ".join(result["error_log"])

    def test_line_items_are_capped_by_the_caller_ceiling(self):
        """The caller may narrow the ceiling; the cap is enforced at parse time."""
        rows = "".join(f"AB-{1000 + i},SupplierA,1\n" for i in range(50))
        content = "part_number,supplier,quantity\n" + rows
        result = ParseBOMFileNode().execute(
            {"input_context": {"bom_content": content, "bom_format": "csv", "max_line_items": 5}}
        )
        assert len(from_json(result["parsed_bom_items_json"])) == 5

    def test_non_mapping_input_context_is_refused(self, node):
        result = node.execute({"user_input": "Validate BOM", "input_context": "not-a-mapping"})
        _assert_refused(result, "bom_content")

    def test_oversized_document_is_refused(self, node):
        result = node.execute(_state(bom_content="part_number,supplier\n" + "AB-1234,S\n" * 60_000))
        _assert_refused(result, "bom_content", code="QUESTION_TOO_LONG")
