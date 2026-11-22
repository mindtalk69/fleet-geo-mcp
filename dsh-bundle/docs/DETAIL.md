# fleet-geo

Adds the **fleet-geo** MCP server to the agent: evidence-first geolocation of the
provider behind every model in the fleet.

Tools appear as `mcp__fleetgeo__locate_model`, `mcp__fleetgeo__fleet_status`,
`mcp__fleetgeo__observe_endpoints`, `mcp__fleetgeo__inspect_connections`, and so on. Supports
dual-stack IPv4/IPv6 evidence (Team Cymru `origin`/`origin6`, AWS/GCP IPv4+IPv6 prefix tables,
RDAP) and an optional Rust N-API native core for direct kernel RFC 1792 TCP/UDP socket snapshots
with automatic pure-JS fallback.

## What it answers

For each lane: **where does inference physically execute?** — with the four planes kept
apart (control / edge / origin / legal), an explicit confidence state, and the next probe
that would tighten the answer.

## Why it does not just say "Cloudflare, San Francisco"

Most models sit behind a CDN. The CDN is the *edge*, nearest to the caller — not where
the weights run. This server refuses to promote an edge PoP to an origin. When the origin
is hidden, it says so and tells you what would settle it.

## The catalog grows by citation

`record_fact` accepts a fact only with a source URL and a verbatim quote. That is how a
lane moves from `OPEN` to `ANCHORED`: read the provider's own page, record it, re-run.

## Install

See [`../fleet-geo-mcp/INSTALL.md`](../fleet-geo-mcp/INSTALL.md).
