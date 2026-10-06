# Boundary test: the entry-point auth boundary — src/api/server.py
#
# Why this file exists (the concrete failure it prevents):
#   ValidateInputNode (src/nodes/validate_input.py) occupies the `pre_process`
#   backbone slot and declares required_trust_level = TrustLevel.VERIFIED_EXTERNAL.
#   Nothing in src/api/ sets request.state.trust_level (there is no middleware in
#   the standalone deployment), so without the Bearer boundary every deployed
#   invoke arrives ANONYMOUS, the trust gate denies it and the agent returns
#   status="error" for every request.
#
# Contract under test:
#   - INVOKE_AUTH_TOKEN set + no / wrong Bearer   -> 401, generic body
#   - INVOKE_AUTH_TOKEN set + correct Bearer      -> not 401, ctx built at
#                                                    VERIFIED_EXTERNAL
#   - INVOKE_AUTH_TOKEN unset                     -> not 401, ctx stays ANONYMOUS
#   - trust already set by middleware             -> preserved, never demoted
#   - input_context supplied by the caller        -> forwarded to the graph
#
# The app is driven through its real ASGI interface rather than
# fastapi.testclient.TestClient on purpose: TestClient needs httpx (only a
# transitive SDK dependency, and it now emits a deprecation warning against
# starlette). A hand-rolled ASGI call keeps this boundary test dependency-free
# so it can never silently skip in CI.
#
# The domain pipeline is stubbed out (see the `recorder` fixture): this file
# tests the ENTRY-POINT auth boundary only, so it must not depend on the
# agent's domain behaviour. End-to-end behaviour through the same entry point
# is covered by tests/integration/test_invoke_api.py.

import asyncio
import json
import os

import pytest

# Importing the module IS the boot check: it constructs the FastAPI app, builds
# the agent, compiles the graph and provisions secrets at import time.
import src.api.server as server_module
from src.api.server import app

_TOKEN = "server-boot-token"
_BOM = "part_number,supplier,quantity\nAB-1234,SupplierA,100\n"
_PAYLOAD = {
    "input": "Validate BOM",
    "session_id": "server-boot",
    "input_context": {"bom_content": _BOM, "bom_format": "csv"},
}


def _post_invoke(
    headers: dict = None,
    state: dict = None,
    payload: dict = None,
):
    """POST /invoke through the real ASGI app. Returns (status_code, body).

    *state* populates ASGI ``scope["state"]``, which is exactly what Starlette
    exposes as ``request.state`` — the channel real auth middleware uses to
    vouch for a caller.
    """
    body = json.dumps(payload if payload is not None else _PAYLOAD).encode()
    raw_headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
    ]
    for key, value in (headers or {}).items():
        # latin-1 is the wire encoding for HTTP headers — the same decoding that
        # makes a str compare_digest() raise TypeError on non-ASCII input.
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
    if state is not None:
        scope["state"] = dict(state)

    messages = []
    sent = {"body": b""}

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        messages.append(message)
        if message["type"] == "http.response.body":
            sent["body"] += message.get("body", b"")

    asyncio.run(app(scope, receive, send))

    start = next(m for m in messages if m["type"] == "http.response.start")
    return start["status"], sent["body"]


class _RecordingAgent:
    """Stands in for the compiled agent so this boundary test never depends on
    the domain pipeline. Records the trust level the entry point resolved."""

    def __init__(self, secrets_provider):
        self._secrets_provider = secrets_provider
        self.trust_level = None
        self.input_context = None

    def invoke(self, user_input, ctx=None, input_context=None):
        self.trust_level = ctx.caller_trust_level
        self.input_context = input_context
        return {"status": "success", "output": ""}


@pytest.fixture
def recorder(monkeypatch):
    """Replace the compiled agent with a recorder, keeping the real secrets
    provider so `bound_secrets(agent._secrets_provider)` behaves unchanged."""
    stub = _RecordingAgent(server_module.agent._secrets_provider)
    monkeypatch.setattr(server_module, "agent", stub)
    return stub


@pytest.fixture
def token_configured(monkeypatch):
    """Server environment with a caller token configured."""
    monkeypatch.setenv("INVOKE_AUTH_TOKEN", _TOKEN)


@pytest.fixture
def token_absent(monkeypatch):
    """Server environment with no caller token configured."""
    monkeypatch.delenv("INVOKE_AUTH_TOKEN", raising=False)


class TestEntryPointAuthBoundary:
    """Standalone caller auth on POST /invoke."""

    def test_module_imports_and_exposes_app(self):
        """Boot check: the module builds an ASGI app without raising."""
        assert callable(app)

    def test_missing_bearer_is_rejected(self, token_configured, recorder):
        """Token configured, no Authorization header -> 401."""
        status, body = _post_invoke()
        assert status == 401, f"expected 401 for missing Bearer, got {status}: {body!r}"
        assert recorder.trust_level is None, "a rejected caller must never reach the agent"

    def test_wrong_bearer_is_rejected(self, token_configured, recorder):
        """Token configured, incorrect Bearer -> 401."""
        status, body = _post_invoke({"Authorization": "Bearer not-the-right-token"})
        assert status == 401, f"expected 401 for wrong Bearer, got {status}: {body!r}"
        assert recorder.trust_level is None

    def test_malformed_authorization_scheme_is_rejected(self, token_configured, recorder):
        """A non-Bearer scheme carrying the right value is still rejected."""
        status, _ = _post_invoke({"Authorization": f"Basic {_TOKEN}"})
        assert status == 401

    def test_empty_bearer_is_rejected(self, token_configured, recorder):
        """An empty Bearer value must not elevate trust."""
        status, _ = _post_invoke({"Authorization": "Bearer "})
        assert status == 401

    def test_non_ascii_bearer_returns_401_not_500(self, token_configured, recorder):
        """Regression guard: compare_digest on str raises TypeError for non-ASCII
        (headers decode as latin-1), which would surface as 500 instead of 401.
        The implementation must compare ENCODED bytes.

        The value is written as escapes so the non-ASCII bytes cannot be lost in
        transit/encoding — it must really be non-ASCII for this to test anything.
        """
        non_ascii = "Bearer t\u00f6k\u00e9n-n\u00f6n-ascii"
        assert not non_ascii.isascii(), "guard value must be non-ASCII"
        status, _ = _post_invoke({"Authorization": non_ascii})
        assert status == 401, "non-ASCII Bearer must be a generic 401, never a 500"

    def test_rejection_body_is_generic(self, token_configured, recorder):
        """The 401 body must not leak the expected token or the failure reason."""
        _, body = _post_invoke()
        assert _TOKEN.encode() not in body
        lowered = body.lower()
        for leak in (b"missing", b"absent", b"malformed", b"expected"):
            assert leak not in lowered, f"401 body leaks failure detail: {body!r}"

    def test_correct_bearer_elevates_to_verified_external(self, token_configured, recorder):
        """Token configured + correct Bearer -> not 401, and the context is built
        at VERIFIED_EXTERNAL — the level ValidateInputNode requires."""
        status, body = _post_invoke({"Authorization": f"Bearer {_TOKEN}"})
        assert status == 200, f"correct Bearer must be accepted, got {status}: {body!r}"
        assert recorder.trust_level is server_module.TrustLevel.VERIFIED_EXTERNAL

    def test_no_token_configured_stays_anonymous(self, token_absent, recorder):
        """No token configured -> callers are not rejected but are NOT elevated;
        an absent token must never silently grant trust."""
        assert os.environ.get("INVOKE_AUTH_TOKEN") is None
        status, body = _post_invoke()
        assert status != 401, f"unconfigured server must not 401: {body!r}"
        assert recorder.trust_level is server_module.TrustLevel.ANONYMOUS

    def test_empty_token_configured_stays_anonymous(self, monkeypatch, recorder):
        """An EMPTY INVOKE_AUTH_TOKEN must not elevate trust either."""
        monkeypatch.setenv("INVOKE_AUTH_TOKEN", "")
        status, _ = _post_invoke({"Authorization": "Bearer "})
        assert status != 401
        assert recorder.trust_level is server_module.TrustLevel.ANONYMOUS

    def test_middleware_established_trust_is_not_demoted(self, token_configured, recorder):
        """A caller already vouched for by upstream middleware skips the Bearer
        check entirely — established trust is never demoted (and no 401 is
        raised even though no Authorization header is present)."""
        status, body = _post_invoke(state={"trust_level": server_module.TrustLevel.INTERNAL})

        assert status != 401, f"middleware-vouched caller must not be challenged: {body!r}"
        assert (
            recorder.trust_level is server_module.TrustLevel.INTERNAL
        ), "INTERNAL trust established by middleware must be preserved, not demoted"


class TestCallerContextForwarding:
    """The structured invocation channel reaches the graph unchanged."""

    def test_input_context_is_forwarded_to_the_graph(self, token_configured, recorder):
        """The BOM record supplied by the caller must arrive at agent.invoke().

        Without this the caller-data contract has no public path: the graph
        would only ever see the request string.
        """
        status, body = _post_invoke({"Authorization": f"Bearer {_TOKEN}"})
        assert status == 200, body
        assert recorder.input_context == {"bom_content": _BOM, "bom_format": "csv"}

    def test_oversized_input_context_is_rejected(self, token_configured, recorder):
        """An oversized structured payload is refused at the adapter, before the graph."""
        oversized = {
            "input": "Validate BOM",
            "session_id": "server-boot",
            "input_context": {"bom_content": "A" * 300_000, "bom_format": "csv"},
        }
        status, _ = _post_invoke({"Authorization": f"Bearer {_TOKEN}"}, payload=oversized)
        assert status == 413
        assert recorder.input_context is None, "an oversized payload must never reach the agent"
