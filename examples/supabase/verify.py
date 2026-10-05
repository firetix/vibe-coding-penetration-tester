"""Exercise real Auth, PostgREST, and PostgreSQL on the disposable local fixture."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import tempfile
import tomllib
import urllib.request
from pathlib import Path
from uuid import UUID

from vibe_pentest.supabase import template

ROOT = Path(__file__).resolve().parents[2]
WORKDIR = ROOT / "examples" / "supabase"
ORIGIN = "http://127.0.0.1:55431"
PROJECT = "vpt-rls-example"
ROW_ID = "33333333-3333-4333-8333-333333333333"
CANARY = "vpt-private-note-fixture-7f38d2"


def sql(statement):
    result = subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            f"supabase_db_{PROJECT}",
            "psql",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
        ],
        input=statement,
        text=True,
        capture_output=True,
    )
    if result.returncode:
        raise RuntimeError("Fixture SQL failed. Check the local example migration.")


def signup(key):
    request = urllib.request.Request(
        ORIGIN + "/auth/v1/signup",
        data=json.dumps(
            {
                "email": f"vpt-{secrets.token_hex(8)}@example.com",
                "password": secrets.token_urlsafe(32),
            }
        ).encode(),
        headers={"apikey": key, "Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=10) as response:
        data = json.load(response)
    return str(UUID(data["user"]["id"])), data["access_token"]


def verify():
    with (WORKDIR / "supabase" / "config.toml").open("rb") as source:
        config = tomllib.load(source)
    if config["project_id"] != PROJECT or config["api"]["port"] != 55431:
        raise RuntimeError("Use the unchanged, disposable example configuration.")
    state = subprocess.run(
        ["supabase", "status", "--workdir", str(WORKDIR), "--output", "json"],
        check=True,
        text=True,
        capture_output=True,
    )
    status = json.loads(state.stdout)
    if status["API_URL"] != ORIGIN:
        raise RuntimeError("Only the dedicated loopback fixture is supported.")
    key = status["ANON_KEY"]
    users = []
    reports = {}
    try:
        alice, alice_token = signup(key)
        users.append(alice)
        bob, bob_token = signup(key)
        users.append(bob)
        # Values are fixed fixture strings or validated UUIDs, never arbitrary SQL input.
        sql(f"insert into public.vpt_notes values ('{ROW_ID}', '{alice}', '{CANARY}');")
        env = {
            **os.environ,
            "VPT_SUPABASE_KEY": key,
            "VPT_ALICE_TOKEN": alice_token,
            "VPT_BOB_TOKEN": bob_token,
        }
        data = template(ORIGIN, table="vpt_notes", owner_id=alice, other_id=bob, row_id=ROW_ID)
        with tempfile.TemporaryDirectory(prefix="vpt-supabase-") as directory:
            contract = Path(directory) / "contract.json"
            contract.write_text(json.dumps(data), encoding="utf-8")

            def check(name, expected, credentials=env):
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        "from vibe_pentest.cli import main; raise SystemExit(main())",
                        "check",
                        str(contract),
                        "--allow-origin",
                        ORIGIN,
                        "--format",
                        "json",
                    ],
                    cwd=ROOT,
                    env=credentials,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                report = json.loads(result.stdout)
                if result.returncode != expected:
                    raise RuntimeError(f"Unexpected result for {name}.")
                reports[name] = report
                coverage = report["coverage"]
                print(
                    f"{name}: {report['status']}, exit {result.returncode}, "
                    f"{coverage['completed_checks']}/{coverage['planned_checks']} checks"
                )

            check("fixed", 0)
            check("publishable-key", 0, {**env, "VPT_SUPABASE_KEY": status["PUBLISHABLE_KEY"]})
            sql("alter table public.vpt_notes disable row level security;")
            check("rls-disabled", 1)
            sql(
                "alter table public.vpt_notes enable row level security; "
                "create policy vpt_public_read on public.vpt_notes for select using (true);"
            )
            check("permissive-policy", 1)
            sql(
                "drop policy vpt_public_read on public.vpt_notes; "
                "drop policy owner_reads on public.vpt_notes;"
            )
            check("owner-blocked", 2)
            sql(
                "create policy owner_reads on public.vpt_notes for select to authenticated "
                "using ((select auth.uid()) = owner_id);"
            )
            check("invalid-session", 2, {**env, "VPT_BOB_TOKEN": "invalid-test-session"})
            check(
                "swapped-sessions",
                2,
                {**env, "VPT_ALICE_TOKEN": bob_token, "VPT_BOB_TOKEN": alice_token},
            )
            check("fixed-again", 0)
    finally:
        sql(
            "alter table public.vpt_notes enable row level security; "
            "drop policy if exists vpt_public_read on public.vpt_notes; "
            "drop policy if exists owner_reads on public.vpt_notes; "
            "create policy owner_reads on public.vpt_notes for select to authenticated "
            "using ((select auth.uid()) = owner_id); "
            f"delete from public.vpt_notes where id = '{ROW_ID}';"
        )
        for user in users:
            sql(f"delete from auth.users where id = '{user}';")
    destination = ROOT / ".cache" / "supabase-verification.json"
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(reports, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    try:
        verify()
    except Exception:
        raise SystemExit(
            "Verification failed. Check that the dedicated local example is running."
        ) from None
