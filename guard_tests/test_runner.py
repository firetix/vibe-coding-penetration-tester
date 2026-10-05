import json

import pytest

from vibe_pentest.contract import Contract, ContractError
from vibe_pentest.demo import fixture, template
from vibe_pentest.report import render
from vibe_pentest.runner import exit_code, run
from vibe_pentest.transport import RequestError, Response

TOKENS = {"VPT_ALICE_TOKEN": "secret-sentinel-alice", "VPT_BOB_TOKEN": "secret-sentinel-bob"}
CANARY = "vpt-private-fixture-alice-7f38d2"


def responder(*, control=None, owner=None, denied=None, fault=None):
    def request(url, token, timeout):
        actor = next(
            (name for name in ("alice", "bob") if token == TOKENS[f"VPT_{name.upper()}_TOKEN"]),
            None,
        )
        if url.endswith("/api/me"):
            if control and actor == "bob":
                return control
            return Response(200, json.dumps({"id": actor, "tenant_id": f"tenant-{actor}"}).encode())
        if actor == "alice":
            return owner or Response(
                200, json.dumps({"id": "invoice-alice", "private_note": CANARY}).encode()
            )
        if fault:
            raise RequestError("Request failed. Check connectivity, TLS, and the target service.")
        return denied or Response(403 if actor else 401, b'{"error":"denied"}')

    return request


def test_local_vulnerable_and_fixed_applications():
    tokens = {"VPT_ALICE_TOKEN": "demo-alice", "VPT_BOB_TOKEN": "demo-bob"}
    for mode, expected in [("vulnerable", 1), ("fixed", 0)]:
        with fixture(mode) as url:
            report = run(Contract.parse(template(url)), tokens)
        assert exit_code(report) == expected
        assert report["coverage"]["requests"] == 5
        assert report["coverage"]["completed_checks"] == 3


@pytest.mark.parametrize(
    "control",
    [
        Response(401, b"{}"),
        Response(200, b'{"id":"alice","tenant_id":"tenant-alice"}'),
        Response(200, b'{"id":"bob","tenant_id":"tenant-alice"}'),
        Response(200, b"<html>login</html>"),
    ],
)
def test_invalid_identity_never_tests_resources(control):
    report = run(Contract.parse(template()), TOKENS, responder(control=control))
    assert exit_code(report) == 2
    assert report["coverage"]["requests"] == 2
    assert report["checks"] == []


@pytest.mark.parametrize(
    "owner",
    [
        Response(404, b"{}"),
        Response(200, b'{"id":"wrong"}'),
        Response(200, b'{"id":"invoice-alice"}'),
        Response(200, b"<html>login</html>"),
    ],
)
def test_missing_owner_fixture_is_inconclusive(owner):
    report = run(Contract.parse(template()), TOKENS, responder(owner=owner))
    assert exit_code(report) == 2
    assert report["coverage"]["requests"] == 3


@pytest.mark.parametrize("status", [200, 201, 302, 400, 429, 500])
def test_ambiguous_denial_never_passes(status):
    report = run(Contract.parse(template()), TOKENS, responder(denied=Response(status, b"{}")))
    assert exit_code(report) == 2


@pytest.mark.parametrize(
    "body",
    [
        b"<html>login</html>",
        b'{"error":"denied","error":"hidden"}',
        b'{"debug":"\\u0076pt-private-fixture-alice-7f38d2","debug":"hidden"}',
        b'{"error":',
        b'{"error":NaN}',
        b'{"error":Infinity}',
        b'{"error":"\xff"}',
        b" ",
    ],
)
def test_invalid_denial_body_is_inconclusive(body):
    report = run(Contract.parse(template()), TOKENS, responder(denied=Response(403, body)))
    assert exit_code(report) == 2
    assert report["coverage"]["completed_checks"] == 1
    assert all(row["status"] == "error" for row in report["checks"][1:])


@pytest.mark.parametrize("body", [b"", b'{"error":"denied"}'])
def test_empty_or_valid_json_denial_can_pass(body):
    report = run(Contract.parse(template()), TOKENS, responder(denied=Response(403, body)))
    assert exit_code(report) == 0
    assert report["coverage"]["completed_checks"] == 3


@pytest.mark.parametrize("status", [200, 401, 403, 404, 500])
def test_leaked_private_data_fails_even_under_error_status(status):
    leaked = json.dumps({"error": "denied", "debug": CANARY}).encode()
    report = run(Contract.parse(template()), TOKENS, responder(denied=Response(status, leaked)))
    assert exit_code(report) == 1
    assert sum(row["status"] == "fail" for row in report["checks"]) == 2


def test_resource_id_without_private_evidence_is_inconclusive():
    report = run(
        Contract.parse(template()),
        TOKENS,
        responder(denied=Response(403, b'{"id":"invoice-alice"}')),
    )
    assert exit_code(report) == 2


def test_token_expiring_after_identity_check_is_inconclusive():
    report = run(
        Contract.parse(template()), TOKENS, responder(denied=Response(401, b'{"error":"expired"}'))
    )
    assert exit_code(report) == 2
    assert report["checks"][1]["actor"] == "bob"
    assert report["checks"][1]["status"] == "error"
    assert report["checks"][2]["actor"] == "anonymous"
    assert report["checks"][2]["status"] == "pass"


def test_network_failure_preserves_partial_coverage():
    report = run(Contract.parse(template()), TOKENS, responder(fault=True))
    assert exit_code(report) == 2
    assert report["coverage"]["completed_checks"] == 1


def test_missing_token_fails_before_network():
    def forbidden(*args):
        pytest.fail("Network must not run")

    with pytest.raises(ContractError):
        run(Contract.parse(template()), {}, forbidden)


@pytest.mark.parametrize("format", ["markdown", "json", "sarif"])
def test_report_omits_credentials_bodies_and_urls(format):
    report = run(
        Contract.parse(template()), TOKENS, responder(denied=Response(200, CANARY.encode()))
    )
    text = render(report, format)
    for secret in [*TOKENS.values(), CANARY, "127.0.0.1", 'invoice-alice"']:
        assert secret not in text
    if format == "sarif":
        sarif = json.loads(text)
        assert len(sarif["runs"][0]["results"]) == 2
        assert sarif["runs"][0]["invocations"][0]["executionSuccessful"]


def test_sarif_marks_incomplete_execution():
    report = run(Contract.parse(template()), TOKENS, responder(fault=True))
    invocation = json.loads(render(report, "sarif"))["runs"][0]["invocations"][0]
    assert not invocation["executionSuccessful"]
    assert invocation["toolExecutionNotifications"]
