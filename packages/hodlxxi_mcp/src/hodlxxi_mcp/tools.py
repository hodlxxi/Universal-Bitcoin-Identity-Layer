from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from .client import Endpoint, HODLXXIReadOnlyClient
from .identifiers import validate_identifier, validate_limit, validate_offset

TOOL_NAMES = (
    "hodlxxi_get_agent_identity",
    "hodlxxi_get_operator_continuity",
    "hodlxxi_get_api_catalog",
    "hodlxxi_get_agent_skills_index",
    "hodlxxi_get_mcp_server_card",
    "hodlxxi_get_nostr_dm_policy",
    "hodlxxi_get_openid_configuration",
    "hodlxxi_get_oauth_authorization_server",
    "hodlxxi_get_oauth_protected_resource",
    "hodlxxi_get_jwks",
    "hodlxxi_get_agent_discovery",
    "hodlxxi_get_capabilities",
    "hodlxxi_get_capabilities_schema",
    "hodlxxi_get_skills",
    "hodlxxi_get_marketplace_listing",
    "hodlxxi_get_reputation",
    "hodlxxi_get_attestations",
    "hodlxxi_get_trust_events",
    "hodlxxi_get_nostr_announcement",
    "hodlxxi_get_chain_health",
    "hodlxxi_get_covenant_countdown",
    "hodlxxi_get_trust_summary",
    "hodlxxi_get_covenant",
    "hodlxxi_get_report",
    "hodlxxi_verify_receipt",
    "hodlxxi_get_receipt",
)


def register_tools(mcp: FastMCP, client: HODLXXIReadOnlyClient) -> None:
    """Register the complete fixed inventory of 26 public read-only tools."""

    @mcp.tool
    async def hodlxxi_get_agent_identity() -> dict[str, Any]:
        """Return the canonical public agent identity document, including capabilities, pricing, endpoints, skills, messaging metadata, and trust-model declarations."""
        return await client.get_json(Endpoint.AGENT_IDENTITY)

    @mcp.tool
    async def hodlxxi_get_operator_continuity() -> dict[str, Any]:
        """Return the public operator-continuity statement, operator and agent public keys, covenant status, rotation policy, and verification references."""
        return await client.get_json(Endpoint.OPERATOR_CONTINUITY)

    @mcp.tool
    async def hodlxxi_get_api_catalog() -> dict[str, Any]:
        """Return the public RFC-style API linkset catalog with service descriptions, documentation links, and status links."""
        return await client.get_json(Endpoint.API_CATALOG)

    @mcp.tool
    async def hodlxxi_get_agent_skills_index() -> dict[str, Any]:
        """Return the Agent Skills discovery index with skill names, descriptions, URLs, types, and SHA-256 digests."""
        return await client.get_json(Endpoint.AGENT_SKILLS_INDEX)

    @mcp.tool
    async def hodlxxi_get_mcp_server_card() -> dict[str, Any]:
        """Return the live MCP discovery server card for https://hodlxxi.com/agent/mcp, which nginx routes to the separate read-only sidecar rather than the Flask monolith."""
        return await client.get_json(Endpoint.MCP_SERVER_CARD)

    @mcp.tool
    async def hodlxxi_get_nostr_dm_policy() -> dict[str, Any]:
        """Return public NIP-17/NIP-59 messaging policy metadata, including intake status, custody limitations, accepted kind, and size ceiling."""
        return await client.get_json(Endpoint.NOSTR_DM_POLICY)

    @mcp.tool
    async def hodlxxi_get_openid_configuration() -> dict[str, Any]:
        """Return OpenID Connect discovery metadata: issuer, authorization and token endpoints, JWKS URI, grants, scopes, PKCE, and signing algorithms."""
        return await client.get_json(Endpoint.OPENID_CONFIGURATION)

    @mcp.tool
    async def hodlxxi_get_oauth_authorization_server() -> dict[str, Any]:
        """Return OAuth authorization-server metadata, including the HODLXXI agent_auth discovery block and disabled registration endpoint references."""
        return await client.get_json(Endpoint.OAUTH_AUTHORIZATION_SERVER)

    @mcp.tool
    async def hodlxxi_get_oauth_protected_resource() -> dict[str, Any]:
        """Return OAuth protected-resource metadata, including resource issuer, authorization servers, JWKS URI, scopes, and bearer method."""
        return await client.get_json(Endpoint.OAUTH_PROTECTED_RESOURCE)

    @mcp.tool
    async def hodlxxi_get_jwks() -> dict[str, Any]:
        """Return the public RSA JSON Web Key Set used to verify HODLXXI-issued JWT signatures. No private JWK fields are exposed."""
        return await client.get_json(Endpoint.JWKS)

    @mcp.tool
    async def hodlxxi_get_agent_discovery() -> dict[str, Any]:
        """Return the signed Agent Protocol discovery document with public endpoint links, trust surfaces, timestamp, and agent signature."""
        return await client.get_json(Endpoint.AGENT_DISCOVERY)

    @mcp.tool
    async def hodlxxi_get_capabilities() -> dict[str, Any]:
        """Return the signed capabilities document with job schemas, pricing, limits, endpoint registry, public skills, and messaging metadata."""
        return await client.get_json(Endpoint.CAPABILITIES)

    @mcp.tool
    async def hodlxxi_get_capabilities_schema() -> dict[str, Any]:
        """Return the JSON Schema published for the signed HODLXXI capabilities document."""
        return await client.get_json(Endpoint.CAPABILITIES_SCHEMA)

    @mcp.tool
    async def hodlxxi_get_skills() -> dict[str, Any]:
        """Return the checked-in public skill catalog with metadata, repository paths, and installation URLs."""
        return await client.get_json(Endpoint.SKILLS)

    @mcp.tool
    async def hodlxxi_get_marketplace_listing() -> dict[str, Any]:
        """Return the normalized marketplace listing with discovery links, job types, pricing, skills, reputation snapshot, chain health, and trust model."""
        return await client.get_json(Endpoint.MARKETPLACE_LISTING)

    @mcp.tool
    async def hodlxxi_get_reputation() -> dict[str, Any]:
        """Return aggregate public operating history, evidenced job counts, attestation count, trust and confidence averages, pattern distribution, and rolling trust trend."""
        return await client.get_json(Endpoint.REPUTATION)

    @mcp.tool
    async def hodlxxi_get_attestations(limit: int = 20, offset: int = 0) -> dict[str, Any]:
        """Return paginated signed receipt attestations. limit must be 1-100 and offset must be non-negative."""
        return await client.get_json(
            Endpoint.ATTESTATIONS,
            query={"limit": validate_limit(limit), "offset": validate_offset(offset)},
        )

    @mcp.tool
    async def hodlxxi_get_trust_events(limit: int = 20, offset: int = 0) -> dict[str, Any]:
        """Return the paginated public trust-event chain with hashes, receipt linkage, timestamps, public key, and signatures."""
        return await client.get_json(
            Endpoint.TRUST_EVENTS,
            query={"limit": validate_limit(limit), "offset": validate_offset(offset)},
        )

    @mcp.tool
    async def hodlxxi_get_nostr_announcement() -> dict[str, Any]:
        """Return the signed Nostr announcement template, advertised NIP-89/NIP-90 kinds, discovery links, and explicit non-goals."""
        return await client.get_json(Endpoint.NOSTR_ANNOUNCEMENT)

    @mcp.tool
    async def hodlxxi_get_chain_health() -> dict[str, Any]:
        """Return attestation-chain continuity status, event count, latest event hashes, and latest timestamp when available."""
        return await client.get_json(Endpoint.CHAIN_HEALTH)

    @mcp.tool
    async def hodlxxi_get_covenant_countdown() -> dict[str, Any]:
        """Return the machine-readable covenant countdown with chain height, spend paths, estimated unlocks, funding status, and conservative trust interpretation."""
        return await client.get_json(Endpoint.COVENANT_COUNTDOWN)

    @mcp.tool
    async def hodlxxi_get_trust_summary(agent_id: str = "hodlxxi-herald-01") -> dict[str, Any]:
        """Return the compact trust summary for a validated public agent identifier."""
        agent_id = validate_identifier(agent_id, label="agent_id")
        return await client.get_json(Endpoint.TRUST_SUMMARY, path_params={"agent_id": agent_id})

    @mcp.tool
    async def hodlxxi_get_covenant(
        covenant_id: str = "hodlxxi-herald-covenant-v1",
    ) -> dict[str, Any]:
        """Return a declared covenant artifact by validated covenant identifier, including descriptor, policy, funding status, public keys, and non-claims."""
        covenant_id = validate_identifier(covenant_id, label="covenant_id")
        return await client.get_json(Endpoint.COVENANT, path_params={"covenant_id": covenant_id})

    @mcp.tool
    async def hodlxxi_get_report(report_id: str) -> dict[str, Any]:
        """Return a public machine-readable trust or readiness report by validated report identifier, including its canonical SHA-256 field when present."""
        report_id = validate_identifier(report_id, label="report_id")
        return await client.get_json(Endpoint.REPORT, path_params={"report_id": report_id})

    @mcp.tool
    async def hodlxxi_verify_receipt(job_id: str) -> dict[str, Any]:
        """Verify a previously issued receipt by job identifier and return verification status, validity, attestation, signed receipt, event hash, and QR pointer non-claims. This does not poll /agent/jobs and cannot mint a receipt."""
        job_id = validate_identifier(job_id, label="job_id")
        return await client.get_json(Endpoint.VERIFY_RECEIPT, path_params={"job_id": job_id})

    @mcp.tool
    async def hodlxxi_get_receipt(job_id: str) -> dict[str, Any]:
        """Return a previously issued signed receipt by job identifier. Optional requester-proof fields depend on the historical receipt."""
        job_id = validate_identifier(job_id, label="job_id")
        return await client.get_json(Endpoint.RECEIPT, path_params={"job_id": job_id})
