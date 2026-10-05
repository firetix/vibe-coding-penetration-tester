import asyncio
import json
import os
import subprocess
import sys
import threading

from vibe_pentest.cli import main
from vibe_pentest.demo import fixture, template


def test_demo_subprocess():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import faulthandler, runpy; "
            "faulthandler.dump_traceback_later(10); "
            "runpy.run_module('vibe_pentest', run_name='__main__', alter_sys=True)",
            "demo",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    reports = json.loads(result.stdout)
    assert reports["vulnerable"]["status"] == "fail"
    assert reports["fixed"]["status"] == "pass"
    assert "demo-alice" not in result.stdout + result.stderr


def test_init_validate_and_no_overwrite(tmp_path, capsys):
    path = tmp_path / "contract.json"
    assert main(["init", "--output", str(path)]) == 0
    original = path.read_bytes()
    assert main(["validate", str(path)]) == 0
    assert "have not been checked" in capsys.readouterr().out
    assert main(["init", "--output", str(path)]) == 2
    assert path.read_bytes() == original


def test_cli_fail_exit_and_atomic_report(tmp_path, monkeypatch):
    monkeypatch.setenv("VPT_ALICE_TOKEN", "demo-alice")
    monkeypatch.setenv("VPT_BOB_TOKEN", "demo-bob")
    path = tmp_path / "contract.json"
    output = tmp_path / "result.json"
    with fixture("vulnerable") as origin:
        path.write_text(json.dumps(template(origin)))
        assert (
            main(
                [
                    "check",
                    str(path),
                    "--allow-origin",
                    origin,
                    "--format",
                    "json",
                    "--output",
                    str(output),
                ]
            )
            == 1
        )
    assert json.loads(output.read_text())["status"] == "fail"


def test_changed_origin_rejected_before_missing_credentials(tmp_path, capsys):
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(template("https://attacker.invalid")))
    assert main(["check", str(path), "--allow-origin", "https://approved.invalid"]) == 2
    assert "origin differs" in capsys.readouterr().err


def test_mcp_real_stdio_roundtrip(tmp_path):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    path = tmp_path / "contract.json"
    with fixture("fixed") as origin:
        path.write_text(json.dumps(template(origin)))

        async def exercise():
            params = StdioServerParameters(
                command=sys.executable,
                args=[
                    "-m",
                    "vibe_pentest",
                    "serve",
                    "--config",
                    str(path),
                    "--allow-origin",
                    origin,
                ],
                env={**os.environ, "VPT_ALICE_TOKEN": "demo-alice", "VPT_BOB_TOKEN": "demo-bob"},
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    tools = await client.list_tools()
                    assert {tool.name for tool in tools.tools} == {
                        "describe_contract",
                        "run_checks",
                    }
                    for tool in tools.tools:
                        assert not tool.inputSchema.get("properties")
                    result = await client.call_tool("run_checks", {})
                    assert not result.isError
                    assert result.structuredContent["status"] == "pass"
                    assert "demo-alice" not in str(result)
                    assert "vpt-private-fixture" not in str(result)

        asyncio.run(exercise())


def test_mcp_rejects_concurrent_run_without_blocking_describe(monkeypatch):
    from vibe_pentest import mcp_server
    from vibe_pentest.contract import Contract

    entered = threading.Event()
    release = threading.Event()

    def slow_run(*args):
        entered.set()
        assert release.wait(timeout=5)
        return {"status": "pass"}

    monkeypatch.setattr(mcp_server, "run", slow_run)
    server = mcp_server.create_server(
        Contract.parse(template()),
        {"VPT_ALICE_TOKEN": "demo-alice", "VPT_BOB_TOKEN": "demo-bob"},
    )

    async def exercise():
        first = asyncio.create_task(server.call_tool("run_checks", {}))
        try:
            assert await asyncio.to_thread(entered.wait, 3)
            second = await server.call_tool("run_checks", {})
            assert "already running" in str(second)
            description = await server.call_tool("describe_contract", {})
            assert "alice-private-invoice" in str(description)
        finally:
            release.set()
            await first

    asyncio.run(exercise())
