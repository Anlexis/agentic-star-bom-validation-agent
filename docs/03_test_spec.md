# Test Specification — MFG-C2-012 Manufacturing BOM Validation Agent

## Test Strategy

- Coverage target: every node execution path (success and both refusal shapes), the caller-data
  contract, the output boundary, and the public HTTP path end to end
- Refusal contract: a refusal the caller can correct is asserted as a COMPLETED run
  (`AgentStatus.SUCCESS`) carrying its reason code and no domain field; a refusal rewording
  cannot fix is asserted as a TERMINATED run (`AgentStatus.ERROR`) with no reason code and no
  output. Assertions are behavioural — status and what is carried forward — never gate wording
- Test types: unit (node-level), boundary, and integration through the real ASGI entry point
- Framework: pytest 8.1.1 (pinned)
- Execution: `python3 -m pytest tests/`
- No model, no network, no external service calls; every test is deterministic
- Screens are tested in BOTH directions: the hostile form is refused AND ordinary domain text is
  not, because a screen that fires on legitimate BOM content blocks real work

## Unit Tests (`tests/unit/test_agent.py`)

### TC-VI: ValidateInputNode (caller-data contract)

| ID | Description | Expected |
|----|-------------|----------|
| TC-VI-01 | Valid CSV bom_content via input_context | SUCCESS + bom_content/bom_format/validated_input set |
| TC-VI-02 | Valid bom_content embedded in user_input JSON (fallback path) | SUCCESS |
| TC-VI-03 | Empty user_input | SUCCESS — correctable refusal; completes, validating nothing |
| TC-VI-04 | Missing bom_content (no input_context, no JSON) | SUCCESS — correctable refusal; completes, validating nothing |
| TC-VI-05 | Unsupported bom_format (e.g. "xlsx") | SUCCESS — correctable refusal; completes, validating nothing |
| TC-VI-06 | bom_content carrying a script tag | ERROR — terminates; rewording cannot fix an active-content construct |
| TC-VI-07 | bom_content > 500 KB | SUCCESS — correctable refusal (size bound); completes, validating nothing |

### TC-PBF: ParseBOMFileNode

| ID | Description | Expected |
|----|-------------|----------|
| TC-PBF-01 | Valid CSV BOM with 3 items | SUCCESS + parsed_bom_items_json (3 items) |
| TC-PBF-02 | Valid XML BOM with 2 items | SUCCESS + parsed_bom_items_json (2 items) |
| TC-PBF-03 | Empty bom_content | SUCCESS — correctable refusal; no line items parsed |
| TC-PBF-04 | Malformed/unclosed XML | SUCCESS — correctable refusal; no line items parsed |

### TC-VPN: ValidatePartNumbersNode

| ID | Description | Expected |
|----|-------------|----------|
| TC-VPN-01 | Part number matching default OEM regex | OK in results |
| TC-VPN-02 | Part number not matching pattern | FAIL in results |
| TC-VPN-03 | Declared part_number_pattern | Declared pattern respected |
| TC-VPN-04 | No parsed items with no refusal marker set | ERROR — terminates; the upstream invariant the node depends on was violated |

### TC-CAS: CheckApprovedSuppliersNode

| ID | Description | Expected |
|----|-------------|----------|
| TC-CAS-01 | Supplier in configured ASL | OK |
| TC-CAS-02 | Supplier absent from configured ASL | FAIL |
| TC-CAS-03 | No ASL configured (empty) | All suppliers OK |

### TC-CRR: CheckRoHSREACHNode

| ID | Description | Expected |
|----|-------------|----------|
| TC-CRR-01 | Part absent from compliance DB | OK (assumed compliant) |
| TC-CRR-02 | RoHS non-compliant | FAIL |
| TC-CRR-03 | REACH concern only (hazardous substances) | WARN |
| TC-CRR-04 | Both RoHS and REACH non-compliant | FAIL |

### TC-CSN: CheckSubstitutionNotesNode

| ID | Description | Expected |
|----|-------------|----------|
| TC-CSN-01 | RoHS/REACH-flagged part with substitution note | OK |
| TC-CSN-02 | Flagged part missing substitution note | FAIL |
| TC-CSN-03 | Non-flagged part (OK RoHS/REACH), no note | OK |

### TC-GVR: GenerateValidationReportNode

| ID | Description | Expected |
|----|-------------|----------|
| TC-GVR-01 | All checks pass | summary.passed=True, fail_count=0 |
| TC-GVR-02 | One check FAIL | summary.passed=False, fail_count=1 |
| TC-GVR-03 | WARN only (no FAIL) | summary.passed=True, warn_count=1 |

### TC-SGO: SecurityGateOutputNode (output boundary)

| ID | Description | Expected |
|----|-------------|----------|
| TC-SGO-01 | Normal-length output | Pass-through as formatted_output |
| TC-SGO-02 | Output beyond the size cap | Truncated with a boundary notice appended |
| TC-SGO-03 | Empty result | Empty formatted_output, SUCCESS |
| TC-SGO-04 | `_security_gate_output` is a module-level function | `inspect.isfunction()` = True |
| TC-SGO-05 | Session identifiers not echoed into formatted_output | session_id absent from output |

## Caller Contract (`tests/unit/test_caller_contract.py`)

| Group | Covers |
|-------|--------|
| max_line_items | Parametrized matrix per form: `NaN`, `Infinity`, `-Infinity` (float and string), numeric strings, bools, non-integral floats, out-of-range magnitudes, containers — all refused; in-range integers accepted; the rejection never echoes the value |
| quantity | `"nan"`, `"inf"`, `"1e5"`, `"0x10"`, `"True"`, negatives, decimals and over-magnitude values fail the document; a digit run is typed to `int`; absent is allowed |
| Rendered alphabets | Out-of-alphabet part numbers, supplier names and embedded newlines fail the document; real manufacturing identifiers (`SKF-6205-2RS`, `EAB64785603`, `48210`, `M8X1.25`, `FLT/AIR-330`) and real supplier names (`Panasonic Parts`, `SKF (Japan)`, `Yamada & Co.`) are accepted |
| Contact screen | Addresses and labelled personal names refused, and the refusal TERMINATES; component labels and grouped-digit part codes NOT treated as personal data; a phone number in a free-text column fails the document and likewise terminates |
| Construct screen | Script tags, PHP tags, code-execution calls, dynamic imports, document-type and entity declarations refused, and the refusal TERMINATES; ordinary prose containing "Evaluate", "System", "Import" unaffected |
| Channel integrity | A document bearing the transit mask marker is refused; the structured channel wins over the request string; non-mapping context refused |
| Refusal shape | Every refusal above is asserted in one of the two shapes through a single helper: a correctable one COMPLETES carrying its reason code (`QUESTION_TOO_LONG` for the size bound, `INVALID_REQUEST` for a mistyped or unusable value) and leaks no validated field; one rewording cannot fix TERMINATES with no reason code. Both halves are asserted — the status, the presence or absence of the code, a recorded reason, and that nothing was carried forward |

## Output Boundary (`tests/unit/test_output_boundary.py`)

| Group | Covers |
|-------|--------|
| Nested traversal | The scan reaches string leaves two levels deep and dictionary keys; scalars and empty structures are handled |
| Credential scan | Each credential class detected nested AND at the top level — the paired control is what distinguishes "the gate is blind" from "the probe is wrong"; a finding withholds both representations |
| Verbatim redaction | The submitted document is redacted from the text AND from the structured report; a short incidental overlap is not |
| Identifier integrity | Ten identifier forms (including a purely numeric code) survive byte-identical; structural counts and section numbers untouched; a mismatch between the two representations withholds the response |
| Size cap | Output beyond the cap is truncated; session identifiers are never echoed |
| Withholding inventory | A withholding refusal terminates and overwrites every field carrying report text or a caller payload, the notice is truthy, inert provenance survives untouched, and both inventories are pinned against the state definition so a field added later cannot quietly join the survivors |
| Violation messages | A withheld notice and the recorded reason name a location and never the matched value; caller-influenced path components are masked while structural ones survive |
| Envelope containment | On a failure, a discarded gate delta and an empty notice each surface no report, while a real notice is still delivered; the success path is untouched |
| Inner output shape | A failed inner run surfaces neither representation; a successful one surfaces both |

## Runtime Configuration (`tests/unit/test_runtime_config.py`)

| Group | Covers |
|-------|--------|
| Shipped file | `config/config.yaml` loads; every declared rule survives validation (a dropped rule would be a dead declaration) |
| Rule validation | Uncompilable patterns, malformed supplier lists and non-finite ceilings are dropped, valid ones forwarded; a missing or unparseable file degrades to no config |
| Liveness | A declared part-number rule, supplier list and line-item ceiling each change the report end to end, with the shipped configuration as the control; the outer graph is constructed WITH the file |

## Integration (`tests/integration/test_invoke_api.py`)

Driven through POST `/invoke` on the real ASGI app with bearer auth and a real compiled graph.

| Group | Covers |
|-------|--------|
| Real work | The report is computed from the submitted document; a different document yields a different report; supplier labels and identifiers render byte-identical |
| Outcome paths | PASS, FAIL from a part-number rule, FAIL from the Approved Supplier List, WARN from a compliance concern, FAIL from a missing substitution note |
| Correctable refusals over the wire | Raw `NaN` / `Infinity` / `-Infinity` literals in the request body (invalid JSON that Python emits and accepts) really arrive — a 422 would mean the contract was never exercised — and the response COMPLETES (HTTP 200, `status: success`) carrying the sentence naming what to correct, with a valid integer as the control; an unsupported format completes the same way and its value appears nowhere in the response, as does a missing document |
| Terminating refusals over the wire | An executable construct and a contact identifier end the run with `status: error` and neither value anywhere in the body; unauthenticated callers rejected before the graph (HTTP 401) |

## Boundary Tests (`tests/proof_of_boundary/`)

### Import isolation (`test_import_isolation.py`)
Verifies no direct platform-SDK (`agenticstar`) imports in `src/`.

### State safety (`test_state_safety.py`)
Verifies `src/schemas/state.py` has no credential fields or prohibited Pydantic types.

### Entry-point auth boundary (`test_server_boot.py`)
Verifies the standalone bearer-token boundary on POST `/invoke`, that a rejected caller never
reaches the agent, that middleware-established trust is never demoted, and that the caller's
`input_context` is forwarded to the graph.

### Invoke order (`test_pb_invoke_order.py`)
Full `ManufacturingBOMValidationAgent().invoke()` over a SUCCESS-yielding CSV BOM payload.
Asserts `node_history` matches the canonical backbone order:
`[InitializeNode, ValidateInputNode, BOMValidationGraphNode, SecurityGateOutputNode, FinalizeNode]`

- `test_invoke_reaches_success`: terminal status = AgentStatus.SUCCESS (required for the post_process slot to run)
- `test_output_is_non_empty`: non-empty `output` in response
- `test_node_history_is_populated`: `node_history` is a non-empty list of strings
- `test_backbone_slot_order`: pre_process → main → post_process strict subsequence
- `test_full_backbone_sequence`: exact 5-node backbone order

## Non-Goals

- Tests against live BOM databases or product-data systems: every run here is offline and
  deterministic, which is what makes a validation verdict reproducible
- Performance and load tests
- Browser or client-side tests
