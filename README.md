# BOM Validation Agent

AI agent for validating bills of materials, built with Agentic Star.

> **Category**: Cat 2 (domain-specific pipeline)
> **Industry**: Manufacturing
> **Template ID**: MFG-C2-012

## Overview

Validates a bill of materials (BOM) against the OEM rules an engineering or procurement team
already works to, and returns a per-line verdict instead of a spreadsheet review. A submitted CSV
or XML BOM is parsed into typed line items, and every item is checked four ways: its part number
against the OEM format rule, its supplier against the Approved Supplier List, its RoHS and REACH
status against the compliance table, and — for any part those checks flag — whether the mandatory
substitution note is present. The result is a report marking each line OK, WARN or FAIL with the
reason attached, plus the counts a reviewer needs to decide whether the BOM can go forward.

Every rule lives in `config/config.yaml`, so a team adapts the agent to its own part-number
convention, supplier list and compliance data without touching code; with no rules configured the
agent still parses and reports, treating unknown parts as compliant. Nothing is looked up
remotely — the run is deterministic and offline, which is what makes a validation verdict
reproducible.

Part numbers, specification codes and quantities are rendered exactly as submitted: the output
boundary checks that identity rather than assuming it, because a report that renames the part it
validated is worse than no report.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from PyPI as a dependency. |
| Python | >=3.11 |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode. If the platform is unreachable or the SDK version does not match, the agent
fails at graph compile / start-up preflight rather than starting in a partially
working state. This is intentional — a half-running agent is worse than one that refuses to start.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

## Project Structure

```
src/          agent implementation (nodes, graphs, schemas)
tests/        unit, integration and boundary tests
config/       agent manifest and runtime rules
docs/         design and operational documentation
```

See `docs/` for the design specification and test specification.

## Customising

1. Put your own rules in `config/config.yaml` — part-number pattern, Approved Supplier List,
   RoHS/REACH table, line-item ceiling.
2. Adapt `src/nodes/parse_bom_file.py` if your BOM export uses different column names.
3. Review `src/nodes/security_gate_output.py` before exposing the agent — it is the boundary
   every response passes through.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.

