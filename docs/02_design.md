# docs/02_design.md — MFG-C2-012 Manufacturing BOM Validation Agent

## Position in AgentCore Architecture

| Field | Value |
|---|---|
| Agent class | ManufacturingBOMValidationAgent |
| L1 Base (framework base class) | AgentBaseGraph — direct framework inheritance |
| Category | Cat 2 (multi-step domain workflow) |
| Industry | MFG (Manufacturing) |
| Pattern | Validation / compliance check |

## Three-Layer Separation

- **State**: flat TypedDict (`src/schemas/state.py`) — no Pydantic, no nested objects; checkpoint-safe
- **Node**: `FunctionNode` inheritance; `execute(self, state) -> dict` returning only changed keys
- **Graph**: composition via `register_nodes()` with two-layer Cat 2 nested architecture

## Architecture Overview

### Cat 2 Nested Architecture

MFG-C2-012 uses the **Cat 2 nested pattern** (two-layer):

**Outer graph** (`src/graph/graph.py` — `ManufacturingBOMValidationAgent`):
- Inherits `AgentBaseGraph` directly
- Fixed 5-node backbone: `initialize → pre_process → main → post_process → finalize`
- `pre_process` slot: `ValidateInputNode` (caller-data contract; `TrustLevel.VERIFIED_EXTERNAL`)
- `main` slot: `BOMValidationGraphNode` (GraphNode subclass → delegates to inner graph)
- `post_process` slot: `SecurityGateOutputNode` (external output boundary; `TrustLevel.ANONYMOUS`)
- `add_edges()` is NOT overridden — backbone wiring belongs to the framework

**Inner graph** (`src/graph/domain_workflow_graph.py` — `BOMValidationWorkflowGraph`):
- Inherits `BaseGraph` (fully custom topology)
- Implements all 7 BaseGraph ABC methods: `name`, `state_schema`, `_validate_config`, `register_nodes`, `add_edges`, `route`, `get_output`
- All inner domain nodes: `TrustLevel.ANONYMOUS` — caller trust is enforced once, at the outer `pre_process` boundary
- Inner nodes instantiated with NO constructor arguments; configuration travels through state

### Node Configuration

| Node | Class | Slot | Trust Level | Responsibility |
|------|-------|------|-------------|----------------|
| initialize | InitializeNode (default) | initialize | — | Set schema_version, session_id, trust_level |
| pre_process | ValidateInputNode | pre_process | VERIFIED_EXTERNAL | Caller-data contract — size, format, line-item ceiling, construct and contact screens |
| main | BOMValidationGraphNode | main | — | GraphNode: delegates to BOMValidationWorkflowGraph |
| (inner) parse_bom_file | ParseBOMFileNode | inner | ANONYMOUS | Parse CSV/XML BOM content into line items and enforce the per-field contract |
| (inner) validate_part_numbers | ValidatePartNumbersNode | inner | ANONYMOUS | Match part numbers against the configured OEM format rule |
| (inner) check_approved_suppliers | CheckApprovedSuppliersNode | inner | ANONYMOUS | Validate suppliers against the configured ASL |
| (inner) check_rohs_reach | CheckRoHSREACHNode | inner | ANONYMOUS | Flag RoHS (2011/65/EU) + REACH (EC 1907/2006) compliance |
| (inner) check_substitution_notes | CheckSubstitutionNotesNode | inner | ANONYMOUS | Verify mandatory substitution notes for flagged parts |
| (inner) generate_validation_report | GenerateValidationReportNode | inner | ANONYMOUS | Compile the per-line OK/WARN/FAIL report in both representations |
| post_process | SecurityGateOutputNode | post_process | ANONYMOUS | External output boundary: credential scan, verbatim redaction, identifier integrity, size cap, audit event |
| finalize | FinalizeNode (default) | finalize | — | Build response_metadata, total_time_ms |

### Data Flow

```
Outer backbone:
  START → initialize → pre_process → main → {route} → post_process → finalize → END
                                         ↓ (retry)
                                      pre_process

  {route} reads `status`, and nothing else:
    SUCCESS → post_process   — a correctable refusal stays on this line, carrying its marker
    ERROR   → finalize       — post_process is skipped and no output is produced

Inside main (BOMValidationGraphNode.execute()):
  a correctable refusal already settled upstream (state["error_code"]) short-circuits here:
  the marker is returned unchanged and the inner workflow is not invoked at all.
  Otherwise:
  extract_input() stashes the validated BOM record on the context channel →
  BOMValidationWorkflowGraph.invoke("validate_bom") →
    _extra_initial_state() re-seeds input_context →
    parse_bom_file → validate_part_numbers → check_approved_suppliers
    → check_rohs_reach → check_substitution_notes → generate_validation_report
  → sub_result → merge_output() → state["result"] + state["validation_report_json"]
  → SecurityGateOutputNode
```

The inner pipeline carries no conditional edge: a correctable refusal travels it as the
`error_code` marker that every domain node reads at the top of `execute()` and returns
unchanged, not as a routing decision. See *Refusal contract* below.

### State Definition (`src/schemas/state.py`)

| Field | Type | Written By | Read By | Purpose |
|-------|------|-----------|---------|---------|
| validated_input | Optional[str] | ValidateInputNode | SecurityGateOutputNode (blocked-field redaction) | Sanitized user_input string |
| bom_content | Optional[str] | ValidateInputNode | ParseBOMFileNode | Raw BOM file content (CSV or XML text) |
| bom_format | Optional[str] | ValidateInputNode | ParseBOMFileNode | "csv" or "xml" |
| max_line_items | Optional[int] | ValidateInputNode | ParseBOMFileNode | Caller ceiling on processed line items (1..5000); may only narrow the configured ceiling |
| parsed_bom_items_json | Optional[str] | ParseBOMFileNode | ValidatePartNumbers, CheckApprovedSuppliers, CheckRoHSREACH, CheckSubstitutionNotes, GenerateValidationReport | JSON-encoded list: [{part_number, supplier, quantity, spec_ref, substitution_note}, ...] |
| part_number_results_json | Optional[str] | ValidatePartNumbersNode | GenerateValidationReportNode | JSON-encoded list: [{part_number, status, message}, ...] |
| supplier_results_json | Optional[str] | CheckApprovedSuppliersNode | GenerateValidationReportNode | JSON-encoded list: [{part_number, supplier, status, message}, ...] |
| rohs_reach_results_json | Optional[str] | CheckRoHSREACHNode | CheckSubstitutionNotesNode, GenerateValidationReportNode | JSON-encoded list: [{part_number, rohs_compliant, reach_compliant, hazardous_substances, status, message}, ...] |
| substitution_results_json | Optional[str] | CheckSubstitutionNotesNode | GenerateValidationReportNode | JSON-encoded list: [{part_number, has_substitution_note, status, message}, ...] |
| validation_report_json | Optional[str] | GenerateValidationReportNode | get_output() | JSON-encoded object: {summary: {...}, line_items: [...]} |
| result | Optional[str] | GenerateValidationReportNode | SecurityGateOutputNode | Human-readable validation report text |
| formatted_output | Optional[str] | SecurityGateOutputNode | Backbone finalize | Screened final output returned to the caller |
| status | Optional[str] | All nodes | All nodes | AgentStatus string value (SUCCESS / ERROR) |
| error_code | Optional[str] | ValidateInputNode, ParseBOMFileNode | BOMValidationGraphNode, every later domain node, SecurityGateOutputNode | Internal marker naming a correctable refusal (`EMPTY_INPUT` / `QUESTION_TOO_LONG` / `INVALID_REQUEST`). It selects the sentence the caller reads and is never part of the returned envelope |
| error_log | List | Any node on a refusal | Backbone | Accumulated refusal and error messages (the internal audit channel — never the caller-facing text) |

**State constraints:**
- Flat TypedDict only (primitives + JSON-serializable types)
- All list/dict domain fields stored as `Optional[str]` (JSON-encoded); use `to_json()` / `from_json()` helpers
- No JWT, API keys or credentials in State (checkpoint leakage risk)
- No Pydantic models, dataclasses, or arbitrary Python objects (not msgpack-serializable)

## Framework Utilization

### Shared Components Used

- `InvocationContext` — correlation_id, session_id, trust_level (via framework)
- `emit_trace_event()` — audit logging in every node (positional form: `event, payload, state`)
- `detect_pii()` — the contact-identifier screen the template applies to the context channel itself
- `TrustLevel` — VERIFIED_EXTERNAL (ValidateInputNode), ANONYMOUS (inner domain nodes and the output boundary)
- `AgentStatus` — SUCCESS / ERROR enum constants (never plain strings)

### Input contract (`ValidateInputNode` + `ParseBOMFileNode`)

The caller controls the document, its format and the line-item ceiling. Each is checked against
explicit bounds, and a rejection names the FIELD, never the submitted value. Whether a given
rejection completes the run or terminates it is the *Refusal contract* below.

- **Document**: string, non-empty, ≤ 500 KB; format restricted to `csv` or `xml`.
- **`max_line_items`**: a finite integer in 1..5000. Strictly typed — a bool, a numeric string, a
  non-integral float, `NaN` or `Infinity` are all refused. `NaN` is the one that matters: every
  comparison against it is False, so an unchecked non-finite ceiling silently disables the bound
  it exists to impose, and Python's `json` module both emits and accepts bare `NaN` / `Infinity`
  over the wire.
- **`quantity`** (inside the document): matched against a digit run, not coerced. `str(float("nan"))`
  is the entirely plausible-looking string `"nan"`, and `int()`/`float()` accept forms a quantity
  should never take.
- **Rendered strings**: `part_number` and `spec_ref` are confined to a bounded identifier alphabet,
  `supplier` to a bounded name alphabet, `substitution_note` to bounded control-character-free text.
  A value outside its alphabet fails the document rather than reaching the report.
- **Executable and markup constructs**: script tags, PHP open tags, code-execution calls, dynamic
  imports, and XML document-type / entity declarations are refused. Each pattern requires the
  construct's real syntax, so ordinary engineering prose ("Evaluate the alternative part") is
  unaffected — a screen that fires on legitimate domain text blocks real work.
- **Contact identifiers**: refused, never masked (see below).

These refusals are enforced by the template itself and are proven by calling `execute()` directly,
with no framework wrapper in front — the agent must behave the same way in a deployment whose
platform gates are absent or configured differently.

### Refusal contract

A run that carries out no validation ends in one of two shapes, and which one it is depends on a
single question: can the caller fix the request?

#### Correctable — the run COMPLETES (`AgentStatus.SUCCESS`), carrying its reason

The deciding node writes a marker into `error_code` and no domain field. Terminating here would
end the calling surface's turn and leave the reason reachable only from the audit trail;
completing lets the caller correct the request and send it again on the same conversation. The
marker is internal — it selects a caller-facing sentence (`src/services/failure_message.py`) that
names WHAT to correct and never echoes the rejected value, names a field path, or quotes a gate
message.

| Trigger | Marker | Settled by |
|---|---|---|
| `user_input` empty, absent or not a string | `EMPTY_INPUT` | ValidateInputNode |
| `bom_content` absent from both the context channel and the request string | `EMPTY_INPUT` | ValidateInputNode |
| `bom_content` beyond the 500 KB bound | `QUESTION_TOO_LONG` | ValidateInputNode |
| `input_context` not a mapping; `bom_content` not a non-empty string; document altered in transit on the fallback channel; `bom_format` unsupported or not a string; `max_line_items` mistyped, non-finite or out of bounds | `INVALID_REQUEST` | ValidateInputNode |
| `bom_content` empty where the workflow begins | `EMPTY_INPUT` | ParseBOMFileNode |
| Per-field contract violation (out-of-alphabet identifier or name, mistyped or over-magnitude quantity, over-length or control-character note); unparseable document; no line items found | `INVALID_REQUEST` | ParseBOMFileNode |

Once the marker is set, no later node computes a verdict on input that was already declined:

- `BOMValidationGraphNode.execute()` returns the marker unchanged and does not invoke the inner
  workflow at all — running it would only produce a second, vaguer reason for the same rejection,
  and overwrite the specific one already settled;
- every inner domain node reads the marker at the top of its own `execute()` and returns it
  unchanged, writing no domain field;
- `SecurityGateOutputNode` renders the sentence matching the marker it receives as the
  caller-facing body (an unrecognised marker falls back to the generic sentence rather than
  leaking the marker itself) and publishes no report, because no BOM was validated.

A marker can be settled on either side of the subgraph boundary, and both reach the caller the
same way. Settled in the outer state, at the request boundary, it is already there when
`SecurityGateOutputNode` reads it. Settled inside the inner workflow, it stops the remaining
domain nodes there and is carried back out by the inner `get_output()` — on its success branch as
well as its non-success one, because a rejection the caller can correct *is* a completion. The
outer `merge_output()` then prefers a reason already settled outside over the one arriving from
within, so an outer rejection is never overwritten by a vaguer inner one.

Both halves of that path are load-bearing. If the inner `get_output()` carried the marker only on
its non-success branch, a rejection settled inside the workflow would arrive at the output
boundary with nothing to render: the run would complete with a success status and an empty body,
which reads to the caller as the agent having nothing to say rather than as a request it can fix.
`tests/integration/test_invoke_api.py` asserts the sentence itself for that case, not the status.

#### Not correctable — the run TERMINATES (`AgentStatus.ERROR`), with no output

No marker is written. The framework's node entry point skips `execute()` on every later node once
`status` is ERROR, and the backbone's conditional edge after `main` sends a non-success run
straight to `finalize` — so `post_process` does not run, and `get_output()` resolves the envelope
body to the output boundary's own withholding notice where one exists and to nothing otherwise.

| Trigger | Settled by |
|---|---|
| Executable or markup construct in the document — script tag, PHP open tag, code-execution call, dynamic import, XML document-type or entity declaration | ValidateInputNode |
| Contact identifier across the whole document — an address, or a labelled personal name | ValidateInputNode |
| Contact identifier in a parsed name or free-text column — an address, phone number, national identifier, card number or labelled personal name, screened per field once the column has been isolated | ParseBOMFileNode |
| Line items absent with no marker set — an upstream invariant the node depends on was violated | ValidatePartNumbers, CheckApprovedSuppliers, CheckRoHSREACH, CheckSubstitutionNotes |
| A part-number rule that cannot be compiled reaching the node (defence in depth: an uncompilable rule is already dropped before forwarding) | ValidatePartNumbersNode |
| Credential pattern anywhere in either representation of the report | SecurityGateOutputNode |
| A part number in the structured report not rendered byte-identical in the text | SecurityGateOutputNode |
| Caller below the trust level the request boundary requires | S-1 trust gate, before `execute()` |

A personal identifier or an active-content construct is not something rewording fixes: the
document must not be carried further whatever the caller sends next, so these terminate rather
than inviting a retry. An invariant violation or an output-boundary finding terminates because
there is no verdict the agent is willing to stand behind.

### Why the BOM record travels on the context channel

The framework masks detected personal names in `user_input` before a node's `execute()` runs, and
the name heuristic matches any two consecutive capitalised words — which is the shape of an
ordinary supplier or component label ("Nippon Bearing", "Main Rotor Assembly"). A BOM routed
through `user_input` therefore reaches the pipeline with `[MASKED]` where its supplier names were:
the report names the wrong parties, and the Approved-Supplier-List comparison is made against the
mask.

So the record travels on `input_context`, which that gate does not scan — and because it does not,
the template screens that channel itself with the framework's own detector, refusing on contact
identifiers (addresses, phone numbers, national identifiers, card numbers, labelled personal
names) rather than masking them. Moving data off a scanned field without adding a screen would be
a fail-open, not a fix. The Latin-script name class is deliberately excluded from the refusal set,
because refusing on it would refuse ordinary BOMs.

The digit-shaped contact classes are screened per FIELD, on the free-text columns only: over the
raw document they would collide with grouped-digit part codes and refuse legitimate work.

The legacy `user_input` JSON channel is retained for direct invocation, and fails closed if the
document arrives bearing the framework's mask marker — a BOM altered in transit gets a refusal,
not a verdict computed from rewritten names.

### Output boundary (`SecurityGateOutputNode`)

A run carrying a correctable-refusal marker has no report to screen: the node renders the sentence
matching that marker as the caller-facing body, publishes no report and completes (see *Refusal
contract*). Everything below applies to a run that produced a report.

The report crosses the boundary in two representations — the text and the structured JSON — and
every layer runs over both. The scan walks nested structures rather than top-level strings only:
the structured report nests caller-derived text two levels deep in `line_items[].findings[]`, and
a top-level-only scan reports nothing there.

1. **Credential scan** — API keys, JWTs, bearer tokens and password assignments anywhere in either
   representation withhold the whole response.
2. **Verbatim caller-text redaction** — the report is a set of computed verdicts, so a verbatim
   embedding of the submitted document or the raw request is bulk re-emission; each is replaced.
3. **Identifier integrity** — every part number in the structured report must appear byte-identical
   in the text report, or the response is withheld.
4. **Size cap** — a report beyond 50 000 characters is truncated, so a malformed upstream state
   cannot turn the response into a bulk BOM dump.

Layers 1 and 3 withhold: the run terminates with no output, and the refusal delta additionally
overwrites `result` and every domain field carrying report text or a caller payload, because the
framework's envelope falls back to `result` whenever the screened output is falsy. Layers 2 and 4
repair the report in place and the run completes.

Each layer emits its own audit event, and a supplier-control audit event records every completed
invocation.

#### Why there is no monetary precision grid

Templates that render monetary aggregates round them onto a fixed grid at the boundary and enforce
that grid in the gate. **MFG-C2-012 renders no monetary aggregate** — its report carries part
numbers, supplier names, quantities, per-line verdicts and counts, and no price, cost or currency
value anywhere. A rounding grid here would have nothing to round, and would be actively harmful:
the grammar such gates use treats any standalone three-letter uppercase word as a currency marker,
which mangles exactly the identifiers this domain is built from (`SKF-6205` → `SKF-6,000`), and a
purely numeric part code has no letters to protect it at all.

So the grid is not applicable, and the invariant enforced in its place is the opposite one:
**a precision identifier reaches the reader byte-identical**. That is checked at the boundary
rather than assumed, and pinned in tests across the identifier forms this domain actually renders,
including a purely numeric code.

### Output-gate design note

The screen is implemented as a **module-level function** `_security_gate_output()` called from
`SecurityGateOutputNode.execute()`. It is NOT an instance method named
`_extra_security_gate_output()`: the framework auto-wraps `_extra_security_gate_*` instance methods
into the graph chain, and a wrapped hook returns `None` on the clean path, which the graph then
passes on as the next node's state.

### GraphNode Contract (`BOMValidationGraphNode`)

| Method | Implementation |
|--------|---------------|
| `_parent_config()` | Validates the `validation` block of `config/config.yaml` and forwards it under `config["configurable"]` |
| `get_subgraph()` | Returns `BOMValidationWorkflowGraph(config=self._parent_config())` (lazy import) |
| `execute()` | Short-circuits on a correctable-refusal marker already in state: returns it unchanged with SUCCESS and never invokes the inner workflow; otherwise delegates to the framework implementation |
| `extract_input()` | Stashes the validated BOM record on the context channel and returns the fixed operation descriptor `"validate_bom"` |
| `merge_output()` | Returns `{"error_code": …, "result": …["output"], "validation_report_json": …["report"], "status": …["status"]}`. A marker already settled in the outer state wins over the sub-result: a reason settled before the inner run is the real one, and an unconditional read of the sub-result would erase it |
| `error_strategy` | `"propagate"` (re-raise inner errors as SubgraphError — fail-fast) |

### Inner Graph Output Contract (`BOMValidationWorkflowGraph.get_output()`)

Two shapes, selected on the inner terminal status:

```python
# SUCCESS — both representations cross the boundary, because the output gate
# screens both and a representation it cannot see is one it cannot protect.
{
    "output":         state.get("result"),                  # report text
    "report":         state.get("validation_report_json"),  # structured report
    "status":         state.get("status"),
    "trace_id":       state.get("trace_id"),
    "correlation_id": state.get("correlation_id"),
    "node_history":   state.get("node_history", []),
}

# non-SUCCESS — no report is surfaced, and the reason leaves the subgraph so the
# outer graph can report it. Surfacing `result` unconditionally would carry a
# report the inner pipeline refused to stand behind into the outer state, where
# the framework envelope falls back to it.
{
    "error_code":     state.get("error_code"),
    "output":         None,
    "report":         None,
    "status":         state.get("status"),
    ...
}
```

## Domain Configuration (`config/config.yaml`, `validation:` block)

| Config Key | Type | Default | Used By |
|------------|------|---------|---------|
| `part_number_pattern` | str (regex) | `^[A-Z]{2,4}-\d{4,8}(-[A-Z0-9]{1,4})?$` | ValidatePartNumbersNode |
| `approved_suppliers` | list[str] | [] (all pass) | CheckApprovedSuppliersNode |
| `rohs_reach_db` | dict[str, dict] | {} (all pass) | CheckRoHSREACHNode |
| `max_line_items` | int (1..50000) | 5000 | ParseBOMFileNode |

All keys are optional with safe defaults; the agent operates without any configuration (all items pass when no rules are configured).

The path is: `_runtime_config()` reads the file → `BOMValidationGraphNode._parent_config()` validates each rule → forwarded under `config["configurable"]` → `BOMValidationWorkflowGraph._extra_initial_state()` republishes it as `agent_config_json` → the domain nodes read it from state. `max_retry` / `timeout_s` from the same file are passed to the outer graph constructor by `src/api/server.py`, mirroring what the platform registry does.

Every rule is validated before it is forwarded, and an unusable one is dropped rather than applied: an uncompilable `part_number_pattern` would fail every part in the BOM, and a non-list `approved_suppliers` would make the membership test behave as "no list configured" and pass every supplier.

## Import Isolation Confirmation

- No `from agenticstar` / `import agenticstar` imports (the platform SDK is never imported directly)
- Import targets: `framework.*` and `shared.*` only
- No imports from `agents/base/` or other templates
- `AgentBaseGraph` + `BaseGraph` are the sole graph base classes

## Design Decision Record

| Decision | Chosen | Rationale |
|----------|--------|-----------|
| Agent base class | AgentBaseGraph | Cat 2 multi-step workflow; direct framework inheritance |
| Inner graph base | BaseGraph | Fully custom linear topology (6 domain nodes — no backbone slots needed) |
| BOM parsing | csv + xml.etree.ElementTree | Standard library only; no external dep; deterministic |
| Part-number validation | Configurable regex | OEM-specific patterns vary; YAML-updatable without code change |
| ASL validation | Set membership | O(1) lookup; pluggable YAML |
| RoHS/REACH check | Configurable dict DB | Mirrors JAMA/IMDS lookup model; absence = no known concern |
| Refusal shape | Correctable completes with SUCCESS + an `error_code` marker; what rewording cannot fix terminates with ERROR | A value the caller can correct is answered on the same conversation instead of ending the turn with only an exception type; a personal identifier, an active-content construct, a violated invariant or an output-boundary finding must stop the run |
| Refusal routing | Backbone conditional edge reads `status`; the marker is read node-by-node, not routed | The inner pipeline is linear and has no conditional edge, so a correctable refusal is carried by each node's own guard on `error_code`; only a terminating refusal changes the route |
| Checkpoint safety | Optional[str] + to_json/from_json | All list/dict fields in state serialized as JSON strings |
| Output-gate implementation | Module-level function called from execute() | Avoids the wrapped-hook None-state failure described above |
| Audit | emit_trace_event() in every node | Supplier-control record keeping (ISO 9001 §8.4) |
