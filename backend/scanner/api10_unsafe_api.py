"""
API10:2023 - Unsafe Consumption of APIs
Tests for unvalidated third-party API data, unvalidated redirects,
and insecure handling of external data sources.
"""
from .base import BaseScanner, ScanConfig
from typing import Dict, Any, List
import asyncio


class UnsafeAPIScanner(BaseScanner):
    VULN_ID = "API10"
    VULN_NAME = "Unsafe Consumption of APIs"
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"

    REDIRECT_PARAMS = ["next", "redirect", "return", "returnUrl", "return_url", "goto", "url", "dest", "destination"]
    INJECTION_PATHS = [
        "/api/v1/search",
        "/api/search",
        "/api/v1/users/search",
    ]
    INJECTION_PAYLOADS = [
        "<script>alert(1)</script>",
        "'; DROP TABLE users; --",
        "${7*7}",
        "{{7*7}}",
        "../../../etc/passwd",
    ]

    async def _test_unvalidated_redirect(self) -> List[Dict]:
        findings = []
        for param in self.REDIRECT_PARAMS[:5]:
            for path in ["/", "/login", "/api/redirect"]:
                url = f"{self.config.target_url}{path}?{param}=https://evil-attacker.com"
                resp = await self.request("GET", url)
                if resp is None:
                    continue
                if resp.status_code in [301, 302, 307, 308]:
                    loc = resp.headers.get("location", "")
                    if "evil-attacker.com" in loc:
                        findings.append({
                            "type": "unvalidated_redirect",
                            "url": url,
                            "parameter": param,
                            "redirects_to": loc,
                            "detail": f"Open redirect via '{param}' parameter — server follows external URLs",
                        })
        return findings

    async def _test_injection_via_external_data(self) -> List[Dict]:
        """
        Test if search/filter endpoints reflect unescaped input,
        which may indicate third-party data is not sanitized.
        """
        findings = []
        for path in self.INJECTION_PATHS:
            url = self.config.target_url + path
            for payload in self.INJECTION_PAYLOADS[:3]:
                resp = await self.request("GET", url, params={"q": payload, "query": payload})
                if resp is None:
                    continue
                if resp.status_code == 200 and payload in resp.text:
                    findings.append({
                        "type": "unescaped_input_reflection",
                        "url": url,
                        "payload": payload,
                        "detail": f"Input '{payload[:30]}' reflected unescaped in response — potential injection",
                    })
        return findings

    async def _test_mixed_content(self) -> List[Dict]:
        """Check if API documentation or responses reference HTTP resources from HTTPS context."""
        findings = []
        resp = await self.request("GET", self.config.target_url)
        if resp and resp.status_code == 200:
            body = resp.text
            # Check for HTTP references in HTTPS contexts
            if self.config.target_url.startswith("https://") and "http://" in body:
                count = body.count("http://")
                if count > 3:
                    findings.append({
                        "type": "mixed_content",
                        "http_references": count,
                        "detail": f"HTTPS API response contains {count} HTTP references — possible mixed content",
                    })
        return findings

    async def _test_third_party_data_exposure(self) -> List[Dict]:
        """Test if the API passes through third-party API errors/data without sanitization."""
        findings = []
        # Try to trigger a third-party API call with controlled input
        for path in ["/api/v1/weather", "/api/weather", "/api/v1/geocode", "/api/geocode"]:
            url = f"{self.config.target_url}{path}?location=INVALID_LOCATION_XYZ"
            resp = await self.request("GET", url)
            if resp and resp.status_code == 200:
                body = resp.text.lower()
                # Check if third-party API error messages leak through
                third_party_errors = ["api key", "rate limit", "quota exceeded", "unauthorized", "invalid api"]
                leaked = [e for e in third_party_errors if e in body]
                if leaked:
                    findings.append({
                        "type": "third_party_error_leakage",
                        "url": url,
                        "leaked_info": leaked,
                        "detail": f"Third-party API errors leaked to client: {leaked}",
                    })
        return findings

    async def scan(self) -> Dict[str, Any]:
        redirect_findings, injection_findings, mixed_findings, tp_findings = await asyncio.gather(
            self._test_unvalidated_redirect(),
            self._test_injection_via_external_data(),
            self._test_mixed_content(),
            self._test_third_party_data_exposure(),
        )

        all_findings = redirect_findings + injection_findings + mixed_findings + tp_findings
        found = len(all_findings) > 0

        evidence = {
            "unvalidated_redirects": redirect_findings,
            "injection_reflections": injection_findings,
            "mixed_content": mixed_findings,
            "third_party_leakage": tp_findings,
            "test_description": (
                "Tested for: unvalidated open redirects, unescaped input reflection "
                "(indicates third-party data not sanitized), mixed HTTP/HTTPS content, "
                "and third-party API error leakage."
            ),
        }
        return self.base_finding(found, evidence)
