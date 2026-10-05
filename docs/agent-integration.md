# Use your existing coding agent

The command-line interface (CLI), skill, and Model Context Protocol (MCP) server use the same checks.
Use the skill for code inspection, fixture setup, and fixes.
Use MCP when your client needs structured tool access.

## Skill

Copy `skills/vpt-authz/` into your project's `.agents/skills/` directory for Codex.
For Claude Code, use the project's `.claude/skills/` directory.
Install the `vpt` command first. Keep the skill local to the project.
Other agents can read [SKILL.md](../skills/vpt-authz/SKILL.md) directly.

Example task:

> Test the changed invoice route on my local app. Create two tenant fixtures, check isolation, fix failures, and retain the test.

The skill instructs the agent to keep credentials out of chat and contract files.
Client-specific discovery still depends on the client's supported skill directories.

## MCP

From a reviewed checkout:

```sh
uv tool install --with 'mcp>=1.26,<2' .
vpt serve --config /absolute/path/vpt-contract.json --allow-origin https://staging.example.com
```

Supply dedicated test tokens through the server process environment.
Do not place real token values in committed client configuration.

Example client configuration:

```json
{
  "mcpServers": {
    "vibe-pentest": {
      "command": "vpt",
      "args": [
        "serve", "--config", "/absolute/path/vpt-contract.json",
        "--allow-origin", "https://staging.example.com"
      ]
    }
  }
}
```

Replace the example origin and path with your approved target and contract.
Ensure the client can find `vpt` and forwards the dedicated token variables.
Client environment handling varies. Follow your client's secret-management instructions.

| Tool | Arguments | Result |
| --- | --- | --- |
| `describe_contract` | None | Actor labels, case labels, and fixed scope |
| `run_checks` | None | Structured, redacted evidence report |

The server snapshots the contract and credentials at startup.
Restart it after token renewal or contract changes.
Only one run executes at a time. Concurrent requests return a busy error.
Standard output carries protocol messages. Standard error carries SDK diagnostics.
Cancellation does not forcibly kill an HTTP request already executing in a worker thread.
The worker retains the run lock until it completes.

The integration test uses a real MCP client over standard input and output.
That proves protocol compatibility, not installation in every graphical agent client.
