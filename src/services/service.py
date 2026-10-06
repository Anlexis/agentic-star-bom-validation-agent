"""AgentCore Platform v1.0"""

# Service layer: domain queries, external API wrappers, data aggregation.
# Must NOT contain business logic, routing, or credentials.
# Nodes call this; this calls the shared service layer for external integrations.
#
# Contract: MFG-C2-012 validates the BOM the caller submits against rules that
# are declared in config/config.yaml, so the bundled build reaches no external
# system and no domain service is wired. This module is the standard
# service-layer seam and is retained deliberately — a deployment that resolves
# its Approved Supplier List or its compliance records from a live product-data
# or compliance backend implements fetch() here, behind the same node contract.

from __future__ import annotations

from typing import Any


class Service:
    """Domain service (seam — see the module retention note above)."""

    async def fetch(self, query: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Fetch domain data for the given query.

        Not implemented in the bundled build — the validation rules come from
        the configuration file. A deployment backed by a live product-data or
        compliance system implements this; raising keeps the unimplemented
        contract explicit rather than silently returning empty data, which
        would read as "no supplier is unapproved".
        """
        raise NotImplementedError("Service.fetch() is a deliberate stub in the bundled build")
