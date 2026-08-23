"""
API8:2023 - Security Misconfiguration
Tests for debug endpoints, verbose errors, CORS misconfigurations,
missing security headers, and exposed documentation.
"""
from .base import BaseScanner, ScanConfig
from typing import Dict, Any, List
import asyncio


class MisconfigScanner(BaseScanner):
    VULN_ID = "API8"
    VULN_NAME = "Security Misconfiguration"
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"

    DEBUG_PATHS = [
        "/api/debug", "/debug", "/api/v1/debug",
        "/swagger", "/swagger-ui", "/swagger-ui.html",
        "/api/docs", "/docs", "/redoc",
        "/openapi.json", "/api/openapi.json",
        "/actuator", "/actuator/env", "/actuator/health",
        "/api/health", "/health",
        "/.env", "/config", "/api/config",
        "/phpinfo.php", "/api/test", "/test",
        "/api/v1/test", "/trace",
    ]

    REQUIRED_SECURITY_HEADERS = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-XSS-Protection",
        "Referrer-Policy",
    ]

    async def _check_debug_endpoints(self) -> List[Dict]:
        findings = []
        tasks = [(p, self.request("GET", self.config.target_url + p)) for p in self.DEBUG_PATHS]
        responses = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)

        for i, resp in enumerate(responses):
            path = self.DEBUG_PATHS[i]
            if isinstance(resp, Exception) or resp is None:
                continue
            if resp.status_code in [200, 201]:
                findings.append({
                    "type": "exposed_endpoint",
                    "url": self.config.target_url + path,
                    "status_code": resp.status_code,
                    "detail": f"Debug/docs endpoint '{path}' is publicly accessible",
                })
        return findings

    async def _check_cors(self) -> List[Dict]:
        findings = []
        test_origins = [
            "https://evil.attacker.com",
            "null",
            "http://localhost:3000",
        ]
        for origin in test_origins:
            resp = await self.request(
                "OPTIONS",
                self.config.target_url + "/api/v1/users",
                extra_headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "Authorization",
                }
            )
            if resp is None:
                continue
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if acao == "*":
                findings.append({
                    "type": "cors_wildcard",
                    "detail": "Access-Control-Allow-Origin: * (wildcard) — any site can read API responses",
                })
            elif acao == origin and origin != "http://localhost:3000":
                findings.append({
                    "type": "cors_reflects_origin",
                    "origin_tested": origin,
                    "detail": f"API reflects arbitrary Origin '{origin}' — possible CORS misconfiguration",
                })
            if acao == "null" or (origin == "null" and acao == "null"):
                findings.append({
                    "type": "cors_null_origin",
                    "detail": "API allows 'null' Origin — can be exploited from sandboxed iframes",
                })
        return findings

    async def _check_security_headers(self) -> List[Dict]:
        findings = []
        resp = await self.request("GET", self.config.target_url)
        if resp is None:
            return findings

        missing = []
        for header in self.REQUIRED_SECURITY_HEADERS:
            if header.lower() not in {k.lower() for k in resp.headers.keys()}:
                missing.append(header)

        if missing:
            findings.append({
                "type": "missing_security_headers",
                "missing": missing,
                "detail": f"Missing {len(missing)} security headers: {', '.join(missing)}",
            })

        # Check for verbose server header
        server = resp.headers.get("server", "")
        x_powered = resp.headers.get("x-powered-by", "")
        if server or x_powered:
            findings.append({
                "type": "verbose_server_header",
                "server": server,
                "x_powered_by": x_powered,
                "detail": f"Server version disclosed: Server={server}, X-Powered-By={x_powered}",
            })
        return findings

    async def _check_verbose_errors(self) -> List[Dict]:
        findings = []
        # Try to trigger a 500 error with malformed input
        for path in ["/api/v1/users/INVALID_ID_!@#", "/api/v1/search?q='; DROP TABLE--"]:
            url = self.config.target_url + path
            resp = await self.request("GET", url)
            if resp and resp.status_code == 500:
                body = resp.text.lower()
                keywords = ["traceback", "stack trace", "exception", "error at line", "syntax error", "mysql", "postgresql"]
                found_kw = [k for k in keywords if k in body]
                if found_kw:
                    findings.append({
                        "type": "verbose_error",
                        "url": url,
                        "keywords_found": found_kw,
                        "detail": f"500 error exposes internal stack trace / database info: {found_kw}",
                    })
        return findings

    async def scan(self) -> Dict[str, Any]:
        debug_findings, cors_findings, header_findings, error_findings = await asyncio.gather(
            self._check_debug_endpoints(),
            self._check_cors(),
            self._check_security_headers(),
            self._check_verbose_errors(),
        )

        all_findings = debug_findings + cors_findings + header_findings + error_findings
        found = len(all_findings) > 0

        evidence = {
            "exposed_endpoints": debug_findings,
            "cors_issues": cors_findings,
            "header_issues": header_findings,
            "error_disclosure": error_findings,
            "total_issues": len(all_findings),
            "test_description": (
                "Checked for: exposed debug/docs endpoints, CORS wildcards, "
                "missing security headers (CSP, HSTS, X-Frame-Options), "
                "and verbose error messages with stack traces."
            ),
        }
        return self.base_finding(found, evidence)
