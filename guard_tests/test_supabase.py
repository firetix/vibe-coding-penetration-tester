import base64
import json

import pytest

from vibe_pentest.cli import main
from vibe_pentest.contract import Contract, ContractError
from vibe_pentest.demo import template as generic_template
from vibe_pentest.report import render
from vibe_pentest.runner import exit_code, run
from vibe_pentest.supabase import public_key, template
from vibe_pentest.transport import Response

KEY = "sb_publishable_test_key_sentinel"
ENV = {"VPT_SUPABASE_KEY": KEY, "VPT_ALICE_TOKEN": "alice-secret", "VPT_BOB_TOKEN": "bob-secret"}


def legacy_key(role):
    payload = base64.urlsafe_b64encode(json.dumps({"role": role}).encode()).decode().rstrip("=")
    return f"header.{payload}.signature"


def responder(*, denial=b"[]", status=200, owner_empty=False, expired=False):
    data = template()

    def request(url, token, timeout, *, headers):
        assert headers == {"apikey": KEY}
        assert token in (ENV["VPT_ALICE_TOKEN"], ENV["VPT_BOB_TOKEN"], None)
        if url.endswith("/auth/v1/user"):
            actor = "alice" if token == ENV["VPT_ALICE_TOKEN"] else "bob"
            if expired and actor == "bob":
                return Response(401, b'{"error":"expired"}')
            return Response(200, json.dumps({"id": data["actors"][actor]["id"]}).encode())
        if token == ENV["VPT_ALICE_TOKEN"]:
            row = {
                "id": data["cases"][0]["resource"]["equals"],
                "body": data["cases"][0]["private"]["equals"],
            }
            return Response(200, json.dumps([] if owner_empty else [row]).encode())
        return Response(status, denial)

    return request


def test_rls_hidden_rows_pass_only_after_owner_control():
    report = run(Contract.parse(template()), ENV, responder())
    assert exit_code(report) == 0
    assert report["isolation"] == "user"
    assert report["coverage"]["completed_checks"] == 3
    assert all(check["http_status"] == 200 for check in report["checks"])
    assert report["checks"][1]["reason"] == "No rows returned for this private record."


def test_policy_that_blocks_everyone_cannot_pass():
    report = run(Contract.parse(template()), ENV, responder(owner_empty=True))
    assert exit_code(report) == 2
    assert report["coverage"]["requests"] == 3
    assert len(report["checks"]) == 1


def test_expired_session_stops_before_any_resource_read():
    report = run(Contract.parse(template()), ENV, responder(expired=True))
    assert exit_code(report) == 2
    assert report["coverage"]["requests"] == 2
    assert report["checks"] == []


@pytest.mark.parametrize(
    "body", [b"{}", b"null", b"false", b"[{}]", b'{"data":[]}', b"", b"[", b"[] []"]
)
def test_ambiguous_200_is_not_an_empty_array_denial(body):
    report = run(Contract.parse(template()), ENV, responder(denial=body))
    assert exit_code(report) == 2


@pytest.mark.parametrize("status", [401, 429, 500])
def test_empty_array_under_error_status_is_inconclusive(status):
    report = run(Contract.parse(template()), ENV, responder(status=status))
    assert exit_code(report) == 2


def test_legacy_contract_does_not_silently_accept_empty_arrays():
    data = template()
    del data["cases"][0]["denial"]
    assert exit_code(run(Contract.parse(data), ENV, responder())) == 2
    contract = Contract.parse(generic_template())
    assert contract.isolation == "tenant"
    assert contract.provider == "generic"


def test_leak_is_found_and_reports_omit_keys_tokens_ids_and_data():
    data = template()
    canary = data["cases"][0]["private"]["equals"]
    report = run(
        Contract.parse(data), ENV, responder(denial=json.dumps([{"body": canary}]).encode())
    )
    assert exit_code(report) == 1
    for format in ("json", "markdown", "sarif"):
        output = render(report, format)
        for secret in [*ENV.values(), canary, data["actors"]["alice"]["id"]]:
            assert secret not in output


@pytest.mark.parametrize(
    "key",
    [
        "",
        "sb_secret_secret",
        legacy_key("service_role"),
        legacy_key("authenticated"),
        "x.!!!.y",
        "a.b.c",
        "sb_publishable_x\r\nx:y",
    ],
)
def test_privileged_and_malformed_keys_fail_before_network(key):
    def forbidden(*args, **kwargs):
        pytest.fail("No request may run with a missing or invalid public key.")

    with pytest.raises(ContractError, match="publishable or legacy anon"):
        run(Contract.parse(template()), {**ENV, "VPT_SUPABASE_KEY": key}, forbidden)


def test_both_public_key_formats_are_supported():
    assert public_key(ENV) == KEY
    key = legacy_key("anon")
    assert public_key({"VPT_SUPABASE_KEY": key}) == key


def test_supabase_tenant_control_rejects_editable_user_metadata():
    data = generic_template()
    data["provider"] = "supabase"
    data["identity"] = {
        "path": "/auth/v1/user",
        "pointer": "/id",
        "tenant_pointer": "/user_metadata/tenant_id",
    }
    with pytest.raises(ContractError, match="server-managed"):
        Contract.parse(data)
    data["identity"]["tenant_pointer"] = "/app_metadata/tenant_id"
    assert Contract.parse(data).isolation == "tenant"


@pytest.mark.parametrize(
    "change",
    [
        {"isolation": "unknown"},
        {"provider": "unknown"},
        {"identity": {"path": "/fake-user", "pointer": "/id"}},
        {"identity": {"path": "/auth/v1/user", "pointer": "/other"}},
    ],
)
def test_supabase_contract_keeps_real_identity_controls(change):
    with pytest.raises(ContractError):
        Contract.parse({**template(), **change})


@pytest.mark.parametrize(
    "options",
    [
        {"table": "notes?owner_id=eq.alice"},
        {"private_column": "id"},
        {"row_id": "bad"},
        {"owner_id": "bad"},
        {"canary": "short"},
    ],
)
def test_preset_rejects_unsafe_or_ambiguous_inputs(options):
    with pytest.raises(ContractError):
        template(**options)


def test_cli_builds_reviewable_contract_without_network_or_overwrite(tmp_path):
    output = tmp_path / "supabase.json"
    args = ["init", "--preset", "supabase", "--output", str(output), "--table", "vpt_notes"]
    assert main(args) == 0
    data = json.loads(output.read_text())
    contract = Contract.parse(data)
    assert contract.cases[0].path.startswith("/rest/v1/vpt_notes?id=eq.")
    assert "owner_id=" not in contract.cases[0].path
    assert main(args) == 2
    assert main(["init", "--table", "notes", "--output", str(tmp_path / "bad.json")]) == 2
