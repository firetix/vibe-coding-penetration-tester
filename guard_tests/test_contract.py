import copy
import json

import pytest

from vibe_pentest.contract import Contract, ContractError, contains_canary, load_contract, matches
from vibe_pentest.demo import template


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", True),
        ("version", 2),
        ("actors", {}),
        ("actors", []),
        ("cases", []),
        ("cases", None),
        ("timeout_seconds", 0),
        ("timeout_seconds", True),
        ("timeout_seconds", float("nan")),
        ("deny_statuses", [200]),
        ("deny_statuses", []),
        ("deny_statuses", [401, 401]),
        ("deny_statuses", [True]),
        ("unknown", "field"),
    ],
)
def test_invalid_root(field, value):
    data = template()
    data[field] = value
    with pytest.raises(ContractError):
        Contract.parse(data)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "file:///etc/passwd",
        "https://user:password@example.com",
        "https://example.com/path",
        "https://example.com?token=secret",
        "https://example.com/#x",
        "https://example.com:0",
        "https://example.com:bad",
        "https://[oops",
        "https://example.com\n",
        "http://localhost:8000",
        "http://127.0.0.1.attacker.test",
        "https://example.com\\@evil.test",
    ],
)
def test_invalid_origin(url):
    data = template(url)
    with pytest.raises(ContractError):
        Contract.parse(data)


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.test/",
        "//evil.test/",
        "/../a",
        "/a/./b",
        "/%2e%2e/",
        "/%252e%252e/",
        "/\\evil.test",
        "/%5cevil.test",
        "/a#fragment",
        "/a b",
        "/a\r\nHost:evil",
        "/%00",
    ],
)
def test_invalid_paths(path):
    data = template()
    data["cases"][0]["path"] = path
    with pytest.raises(ContractError):
        Contract.parse(data)


def test_invalid_actor_and_marker_definitions():
    changes = [
        lambda d: d["actors"]["bob"].update(id="alice"),
        lambda d: d["actors"]["bob"].update(tenant="tenant-alice"),
        lambda d: d["actors"]["bob"].update(token_env="AWS_SECRET_ACCESS_KEY"),
        lambda d: d["actors"].update(anonymous=d["actors"]["alice"]),
        lambda d: d["cases"].append(copy.deepcopy(d["cases"][0])),
        lambda d: d["cases"][0].update(owner="missing"),
        lambda d: d["cases"][0]["resource"].update(pointer="/bad~3"),
        lambda d: d["cases"][0]["resource"].update(equals=True),
        lambda d: d["cases"][0]["private"].update(equals="short"),
    ]
    for change in changes:
        data = template()
        change(data)
        with pytest.raises(ContractError):
            Contract.parse(data)


def test_credentials_are_dedicated_distinct_and_safe():
    contract = Contract.parse(template())
    for tokens in [
        {},
        {"VPT_ALICE_TOKEN": "x", "VPT_BOB_TOKEN": "x"},
        {"VPT_ALICE_TOKEN": "x\r\nHost: evil", "VPT_BOB_TOKEN": "y"},
    ]:
        with pytest.raises(ContractError):
            contract.credentials(tokens)
    assert (
        contract.credentials({"VPT_ALICE_TOKEN": "abc", "VPT_BOB_TOKEN": "xyz"})["alice"] == "abc"
    )


def test_origin_requires_separate_operator_confirmation():
    contract = Contract.parse(template())
    contract.authorize_origin("http://127.0.0.1:8000/")
    with pytest.raises(ContractError):
        contract.authorize_origin("https://different.example")


def test_loading_limits_and_duplicate_keys(tmp_path):
    path = tmp_path / "contract.json"
    for raw in ['{"version":1,"version":1}', "{bad", " " * (256 * 1024 + 1), b"\xff"]:
        path.write_bytes(raw if isinstance(raw, bytes) else raw.encode())
        with pytest.raises(ContractError):
            load_contract(path)
    path.write_text(json.dumps(template()))
    assert load_contract(path).cases[0].owner == "alice"


def test_json_pointer_and_strict_types():
    body = json.dumps({"a/b": {"~": ["value"]}, "id": True}).encode()
    assert matches(body, "/a~1b/~0/0", "value")
    assert not matches(body, "/a~1b/~0/-1", "value")
    assert not matches(body, "/id", 1)
    assert not matches(b'{"id":"x","id":"y"}', "/id", "y")
    assert not matches(b"<html>login</html>", "/id", "x")


def test_private_canary_detected_in_relocated_and_escaped_values():
    canary = "private-fixture-1234"
    assert contains_canary(json.dumps({"error": {"leak": canary}}).encode(), canary)
    assert contains_canary(b'{"error":"private-fixture-123\\u0034"}', canary)
    assert contains_canary(f"<html>{canary}</html>".encode(), canary)
    assert not contains_canary(b'{"error":"denied"}', canary)
