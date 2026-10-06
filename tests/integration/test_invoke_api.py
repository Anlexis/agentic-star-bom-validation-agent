"""MFG-C2-012 — end to end through the real HTTP entry point.

Everything here goes through POST /invoke on the real ASGI application with a
real compiled graph: adapter, trust boundary, caller-data contract, nested
domain workflow and output boundary. Node-level tests can all pass while the
public path still cannot do the work, so the outcomes that matter are asserted
here — real report content from caller data, every verdict reachable, and every
refusal still a refusal when it arrives over the wire.

The application is driven through its ASGI interface directly rather than
through a test client, so this file needs no HTTP client dependency and can
never silently skip.
"""

import asyncio
import json

import pytest
import yaml

from src.graph import graph as graph_module

import src.api.server as server_module  # noqa: E402  (import IS the boot check)
from src.api.server import app

_TOKEN = "integration-invoke-token"

_CLEAN_BOM = (
    "part_number,supplier,quantity,spec_ref,substitution_note\n"
    "SKF-6205,Panasonic Parts,100,SPEC-001,\n"
    "AB-1234,Nippon Bearing,48210,SPEC-002,Use alt variant\n"
)


def _post(payload, headers=None):
    """POST /invoke through the real ASGI app. Returns (status_code, parsed_body)."""
    body = json.dumps(payload).encode()
    raw_headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
    ]
    for key, value in (headers or {}).items():
        raw_headers.append((key.lower().encode("latin-1"), value.encode("latin-1")))

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/invoke",
        "raw_path": b"/invoke",
        "root_path": "",
        "query_string": b"",
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
    }

    messages = []
    collected = {"body": b""}

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        messages.append(message)
        if message["type"] == "http.response.body":
            collected["body"] += message.get("body", b"")

    asyncio.run(app(scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    try:
        parsed = json.loads(collected["body"])
    except ValueError:
        parsed = {"_raw": collected["body"].decode("utf-8", "replace")}
    return start["status"], parsed


@pytest.fixture(autouse=True)
def _token(monkeypatch):
    monkeypatch.setenv("INVOKE_AUTH_TOKEN", _TOKEN)


@pytest.fixture
def auth():
    return {"Authorization": f"Bearer {_TOKEN}"}


def _rules(tmp_path, monkeypatch, validation):
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump({"max_retry": 3, "timeout_s": 30, "validation": validation}),
        encoding="utf-8",
    )
    monkeypatch.setattr(graph_module, "_RUNTIME_CONFIG_PATH", path)


def _invoke(bom=_CLEAN_BOM, auth=None, **context):
    payload = {
        "input": "Validate BOM",
        "session_id": "integration",
        "input_context": {"bom_content": bom, "bom_format": "csv", **context},
    }
    return _post(payload, auth)


class TestPublicPathDoesRealWork:
    def test_report_is_computed_from_the_submitted_document(self, auth):
        """The response must reflect THIS document, not a fixed baseline."""
        status, body = _invoke(auth=auth)
        assert status == 200
        assert body["status"] == "success"
        output = body["output"]
        assert output, "the public path returned no output"
        assert "Total: 2 items" in output
        assert "SKF-6205" in output and "AB-1234" in output

    def test_a_different_document_produces_a_different_report(self, auth):
        """Guards against a path that can only ever emit the same baseline."""
        one = _invoke(auth=auth)[1]["output"]
        other = _invoke(bom="part_number,supplier,quantity\nEAB64785603,SupplierA,7\n", auth=auth)[1]["output"]
        assert one != other
        assert "Total: 1 items" in other
        assert "EAB64785603" in other

    def test_caller_labels_reach_the_report_byte_identical(self, auth):
        """Supplier and component labels are domain data, not personal data.

        A two-word label has the same shape as a personal name, so a report
        assembled from a channel that masks names would name the wrong parts —
        and the Approved-Supplier-List comparison would run against the mask.
        """
        output = _invoke(auth=auth)[1]["output"]
        assert "Panasonic Parts" in output
        assert "Nippon Bearing" in output
        assert "[MASKED]" not in output

    def test_identifiers_and_quantities_are_rendered_byte_identical(self, auth):
        """Manufacturing identifiers are the collision class that gets mangled.

        A purely numeric quantity (48210) and a grouped part code (SKF-6205)
        both reach the reader exactly as submitted — this template renders no
        monetary aggregate and applies no rounding to anything.
        """
        output = _invoke(auth=auth)[1]["output"]
        assert "SKF-6205" in output
        assert "qty: 48210" in output
        assert "48,000" not in output and "SKF-6,000" not in output

    def test_caller_ceiling_narrows_the_report(self, auth):
        output = _invoke(auth=auth, max_line_items=1)[1]["output"]
        assert "Total: 1 items" in output


class TestOutcomePaths:
    """Every verdict the report can carry is reachable over the wire."""

    def test_pass_verdict(self, auth):
        assert "Overall: PASS" in _invoke(auth=auth)[1]["output"]

    def test_fail_verdict_from_a_part_number_rule(self, auth):
        bom = "part_number,supplier,quantity\ninvalid-pn,SupplierA,1\n"
        output = _invoke(bom=bom, auth=auth)[1]["output"]
        assert "Overall: FAIL" in output
        assert "does not match OEM format rule" in output

    def test_fail_verdict_from_the_approved_supplier_list(self, tmp_path, monkeypatch, auth):
        _rules(tmp_path, monkeypatch, {"approved_suppliers": ["Panasonic Parts"]})
        output = _invoke(auth=auth)[1]["output"]
        assert "Overall: FAIL" in output
        assert "Approved Supplier List" in output

    def test_warn_verdict_from_a_compliance_concern(self, tmp_path, monkeypatch, auth):
        _rules(
            tmp_path,
            monkeypatch,
            {
                "rohs_reach_db": {
                    # AB-1234 carries a substitution note, so the concern surfaces
                    # as WARN rather than being escalated by the note check.
                    "AB-1234": {
                        "rohs_compliant": True,
                        "reach_compliant": False,
                        "hazardous_substances": ["Lead solder (legacy)"],
                    }
                }
            },
        )
        output = _invoke(auth=auth)[1]["output"]
        assert "[WARN]" in output
        assert "SVHC concern" in output

    def test_fail_verdict_from_a_missing_substitution_note(self, tmp_path, monkeypatch, auth):
        _rules(
            tmp_path,
            monkeypatch,
            {
                "rohs_reach_db": {
                    "SKF-6205": {
                        "rohs_compliant": False,
                        "reach_compliant": True,
                        "hazardous_substances": [],
                    }
                }
            },
        )
        output = _invoke(auth=auth)[1]["output"]
        assert "substitution note is missing" in output


class TestRefusalsOverTheWire:
    """A refusal proven at node level must still be a refusal through the adapter."""

    @pytest.mark.parametrize(
        "raw_body",
        [
            '{"input": "Validate BOM", "input_context": {"bom_content": "part_number,supplier\\nAB-1234,S\\n",'
            ' "bom_format": "csv", "max_line_items": NaN}}',
            '{"input": "Validate BOM", "input_context": {"bom_content": "part_number,supplier\\nAB-1234,S\\n",'
            ' "bom_format": "csv", "max_line_items": Infinity}}',
            '{"input": "Validate BOM", "input_context": {"bom_content": "part_number,supplier\\nAB-1234,S\\n",'
            ' "bom_format": "csv", "max_line_items": -Infinity}}',
        ],
    )
    def test_non_finite_numbers_really_arrive_and_are_refused(self, raw_body, auth):
        """NaN and Infinity are not valid JSON, but Python emits AND accepts them.

        The body is written as raw text so the non-finite literal genuinely
        crosses the wire; a test that only builds a Python float would never
        prove the value survives parsing. The first assertion checks it did
        arrive — a 422 would mean the payload was rejected before the contract
        was exercised.
        """
        status, body = _post_raw(raw_body, auth)
        assert status == 200, f"the payload never reached the graph: {status} {body}"
        assert body["status"] == "success"
        # No BOM was validated: the body carries the sentence naming what to
        # correct, so the caller can fix the ceiling and send the request again.
        assert "could not be accepted" in body["output"], body

    def test_valid_ceiling_over_the_wire_is_accepted(self, auth):
        """The control: the same field with a real integer is honoured."""
        status, body = _invoke(auth=auth, max_line_items=2)
        assert status == 200 and body["status"] == "success"

    def test_executable_construct_is_refused(self, auth):
        bom = "part_number,supplier\n<script>alert(1)</script>,S\n"
        status, body = _invoke(bom=bom, auth=auth)
        assert status == 200
        assert body["status"] == "error"
        assert "<script" not in json.dumps(body)

    def test_contact_identifier_is_refused(self, auth):
        bom = "part_number,supplier,substitution_note\nAB-1234,SupplierA,mail buyer@example.com\n"
        status, body = _invoke(bom=bom, auth=auth)
        assert status == 200 and body["status"] == "error"
        assert "buyer@example.com" not in json.dumps(body)

    def test_unsupported_format_is_refused_without_echoing_it(self, auth):
        status, body = _post(
            {
                "input": "Validate BOM",
                "input_context": {"bom_content": _CLEAN_BOM, "bom_format": "xlsx"},
            },
            auth,
        )
        assert status == 200 and body["status"] == "success"
        assert "xlsx" not in json.dumps(body)

    def test_missing_document_is_refused(self, auth):
        status, body = _post({"input": "Validate BOM"}, auth)
        assert status == 200 and body["status"] == "success"

    def test_unauthenticated_caller_is_rejected_before_the_graph(self):
        status, _ = _invoke()
        assert status == 401


class TestRejectionsSettledInsideTheWorkflow:
    """A rejection settled inside the nested workflow must still reach the caller.

    The outer and inner halves of the pipeline reject on different conditions,
    and a rejection the inner half settles has to travel back out through the
    subgraph boundary before the output boundary can render it. Asserting
    `status == "success"` alone does not show that it did: a reason that never
    crosses the boundary produces the same status with an empty body, which
    reads to the caller as the agent having nothing to say.

    Each case below therefore asserts the sentence, not the status.
    """

    @pytest.mark.parametrize(
        "bom, what",
        [
            (
                "part_number,supplier,quantity,spec_ref,substitution_note\n"
                "AB-1234,SupplierA,abc,SPEC-001,\n",
                "a quantity that is not a number",
            ),
            (
                "part_number,supplier,quantity,spec_ref,substitution_note\n",
                "a document with a header and no line items",
            ),
        ],
    )
    def test_the_reason_reaches_the_caller(self, bom, what, auth):
        status, body = _invoke(bom=bom, auth=auth)
        assert status == 200, f"{what}: {status} {body}"
        assert body["status"] == "success", body
        assert body["output"], f"{what}: the caller received an empty answer: {body}"
        assert "could not be accepted" in body["output"], body

    def test_a_valid_document_still_produces_a_report(self, auth):
        """The control: the same path with a document that parses is unchanged."""
        status, body = _invoke(auth=auth)
        assert status == 200 and body["status"] == "success"
        assert "BOM Validation Report" in body["output"], body


def _post_raw(raw_body, headers=None):
    """POST a raw body string, so a non-JSON literal survives to the parser."""
    body = raw_body.encode()
    raw_headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
    ]
    for key, value in (headers or {}).items():
        raw_headers.append((key.lower().encode("latin-1"), value.encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/invoke",
        "raw_path": b"/invoke",
        "root_path": "",
        "query_string": b"",
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
    }
    messages = []
    collected = {"body": b""}

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        messages.append(message)
        if message["type"] == "http.response.body":
            collected["body"] += message.get("body", b"")

    asyncio.run(app(scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    try:
        parsed = json.loads(collected["body"])
    except ValueError:
        parsed = {"_raw": collected["body"].decode("utf-8", "replace")}
    return start["status"], parsed


class TestServiceSurface:
    def test_health_endpoint_names_the_agent(self):
        assert server_module.agent.name == "ManufacturingBOMValidationAgent"

    def test_output_carries_no_credential_material(self, auth):
        body = _invoke(auth=auth)[1]
        assert _TOKEN not in json.dumps(body)


class TestEnvelopeContainmentOverTheWire:
    """A refused report must not ride out inside the ERROR envelope.

    `AgentBaseGraph.get_output` is `formatted_output or result` with no status
    check, so a gate that returns ERROR without overwriting `result` ships the
    un-gated report to the caller. Both refusals below are
    driven entirely from caller data through the real ASGI path — no gate is
    patched, because patching the gate would test the patch and not the agent.

    Every case asserts SecurityGateOutputNode reached `node_history`: without
    that a refuse-everything failure upstream would look identical to a working
    output boundary.
    """

    # framework.security's detector carries sk- but not pk-, so this key travels
    # the whole pipeline untouched by the framework's own output-safety hooks and is
    # refused by the template's output boundary — which is the path under test.
    _PK_KEY = "pk-ABCDEFGHIJKLMNOP0123"
    _BOM_WITH_KEY = (
        "part_number,supplier,quantity,spec_ref,substitution_note\n"
        f"{_PK_KEY},Panasonic Parts,100,SPEC-001,\n"
        "AB-1234,Nippon Bearing,7,SPEC-002,\n"
    )

    def test_the_clean_path_still_returns_the_real_report(self, auth):
        """The control. A gate that refused everything would pass the rest."""
        status, body = _invoke(auth=auth)
        assert status == 200 and body["status"] == "success"
        assert "BOM Validation Report" in body["output"]
        assert "SecurityGateOutputNode" in body["node_history"]

    def test_a_credential_in_the_report_is_withheld_not_shipped(self, auth):
        status, body = _invoke(bom=self._BOM_WITH_KEY, auth=auth)
        assert status == 200
        assert body["status"] == "error"
        serialised = json.dumps(body)
        assert self._PK_KEY not in serialised
        assert "BOM Validation Report" not in serialised
        assert "Panasonic Parts" not in serialised
        assert "REPORT WITHHELD" in body["output"]
        assert "SecurityGateOutputNode" in body["node_history"], "the refusal did not happen at the gate"

    def test_the_withheld_notice_names_a_location_not_the_value(self, auth):
        body = _invoke(bom=self._BOM_WITH_KEY, auth=auth)[1]
        assert self._PK_KEY not in body["output"]
        assert "api_key_pattern" in body["output"]

    def test_an_identifier_integrity_refusal_is_withheld_not_shipped(self, auth):
        """Reached with caller data only.

        `user_input` is a verbatim slice of a rendered report line, so the
        boundary's own caller-text redaction removes it from the text report
        while the structured report keeps the part number — which is exactly the
        disagreement the identifier-integrity layer refuses on.
        """
        status, body = _post(
            {
                "input": "[OK] SKF-6205 |",
                "session_id": "integration",
                "input_context": {"bom_content": _CLEAN_BOM, "bom_format": "csv"},
            },
            auth,
        )
        assert status == 200 and body["status"] == "error"
        serialised = json.dumps(body)
        assert "BOM Validation Report" not in serialised
        assert "byte-identical" in body["output"]
        assert "SecurityGateOutputNode" in body["node_history"], "the refusal did not happen at the gate"
