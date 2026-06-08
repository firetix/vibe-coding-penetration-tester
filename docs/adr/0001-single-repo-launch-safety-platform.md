# ADR 0001: Single-repo Launch Safety Platform

## Status

Accepted.

## Context

The product needs a public freemium surface that can attract vibe-coded entrepreneurs through free URL scorecards and practical launch-safety content on X and YouTube.

The existing scanner already provides a web app, CLI, hosted-mode hooks, and validated web-vulnerability reports. A separate MCP repository already provides vulnerability intelligence tools for CVE lookup, EPSS, CVSS, exploit availability, VEX, timeline, and package-risk checks.

Keeping the SaaS scanner and MCP workflow as separate public repos would split positioning, documentation, onboarding, and launch-safety proof points.

## Decision

Use this repository as the single public Launch Safety platform repository.

Import the vulnerability-intelligence MCP server as an isolated subproject at `mcp/vulnerability-intelligence/`. Keep its own `pyproject.toml`, tests, Docker config, and docs inside that boundary.

## Consequences

The public repo can market one product promise: free scorecard first, deeper MCP/CLI and SaaS workflows after.

The web scanner and MCP server can share product language, examples, docs, and future scorecard/report concepts without forcing immediate dependency unification.

The root Python package remains unchanged for now. Any future dependency sharing between the scanner and MCP server should be a deliberate follow-up, not an accidental import side effect.
