import json

from core.juice_shop_probe import JuiceShopProbe, ProbeResponse


def test_juice_shop_probe_returns_validated_evidence_backed_findings():
    product = {
        "id": 9,
        "name": "Original Product",
        "description": "Original description",
        "price": 1.99,
        "image": "original.png",
    }
    calls = []

    def requester(method, path, data=None, headers=None):
        calls.append((method, path, data, headers))

        if path == "/rest/admin/application-configuration":
            return ProbeResponse(
                200,
                {},
                json.dumps(
                    {"config": {"application": {"name": "OWASP Juice Shop"}}}
                ),
            )

        if path == "/rest/user/login" and data["email"] == "' or 1=1;--":
            return ProbeResponse(
                200,
                {},
                json.dumps(
                    {
                        "authentication": {
                            "token": "admin.jwt",
                            "bid": 1,
                            "umail": "admin@juice-sh.op",
                        }
                    }
                ),
            )

        if path == "/rest/user/login" and data["email"] == "'":
            return ProbeResponse(
                500,
                {},
                "<html><ul id='stacktrace'>Sequelize sqlite query.js</ul></html>",
            )

        if path == "/rest/basket/1":
            return ProbeResponse(
                200,
                {},
                json.dumps({"status": "success", "data": {"UserId": 1}}),
            )

        if path == "/rest/basket/2":
            return ProbeResponse(
                200,
                {},
                json.dumps(
                    {
                        "status": "success",
                        "data": {"UserId": 2, "Products": [{"id": 4}]},
                    }
                ),
            )

        if path == "/api/Products/9" and method == "GET":
            return ProbeResponse(
                200, {}, json.dumps({"status": "success", "data": product})
            )

        if path == "/api/Products/9" and method == "PUT":
            product.update(data)
            return ProbeResponse(
                200, {}, json.dumps({"status": "success", "data": product})
            )

        return ProbeResponse(404, {}, "")

    findings = JuiceShopProbe(
        "http://127.0.0.1:3000", requester=requester
    ).run()

    assert {finding["vulnerability_type"] for finding in findings} == {
        "SQL Injection Authentication Bypass",
        "Verbose SQL Error Disclosure",
        "Broken Object Level Authorization (Basket IDOR)",
        "Broken Access Control on Product API",
    }
    assert all(finding["validated"] is True for finding in findings)
    assert all(finding["details"]["evidence"] for finding in findings)
    assert all(finding["target"] for finding in findings)
    assert all(finding["severity"] for finding in findings)
    assert all(finding["details"]["reproduction_steps"] for finding in findings)
    assert product["name"] == "Original Product"
    assert any(call[0] == "PUT" and call[1] == "/api/Products/9" for call in calls)


def test_juice_shop_probe_skips_non_juice_shop_targets():
    calls = []

    def requester(method, path, data=None, headers=None):
        calls.append((method, path))
        if path == "/rest/admin/application-configuration":
            return ProbeResponse(
                200,
                {},
                json.dumps({"config": {"application": {"name": "Not Juice"}}}),
            )
        if path == "/":
            return ProbeResponse(200, {}, "<html>ordinary app</html>")
        raise AssertionError(f"Unexpected probe request: {method} {path}")

    findings = JuiceShopProbe("http://example.test", requester=requester).run()

    assert findings == []
    assert calls == [("GET", "/rest/admin/application-configuration"), ("GET", "/")]
