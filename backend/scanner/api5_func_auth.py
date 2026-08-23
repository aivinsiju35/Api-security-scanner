"""
API5:2023 - Broken Function Level Authorization
Tests whether regular users can access admin/privileged API functions
by directly calling admin endpoints.
"""
from .base import BaseScanner, ScanConfig
from typing import Dict, Any, List
import asyncio


class FuncAuthScanner(BaseScanner):
    VULN_ID = "API5"
    VULN_NAME = "Broken Function Level Authorization"
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"

    ADMIN_PATHS = [
        "/api/admin",
        "/api/admin/users",
        "/api/v1/admin",
        "/api/v1/admin/users",
        "/admin",
        "/admin/users",
        "/api/admin/dashboard",
        "/api/management",
        "/api/v1/management",
        "/api/admin/stats",
        "/api/internal",
        "/api/v1/internal",
        "/api/admin/config",
        "/api/superadmin",
    ]

    HTTP_METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "PATCH"]

    async def _test_admin_path(self, path: str) -> List[Dict]:
        url = self.config.target_url + path
        findings = []

        # Test with regular user auth (or no auth if no token provided)
        for method in ["GET", "POST"]:
            resp = await self.request(method, url)
            if resp is None:
                continue

            # If we get 200 or 201 — admin endpoint is accessible
            if resp.status_code in [200, 201]:
                findings.append({
                    "url": url,
                    "method": method,
                    "status_code": resp.status_code,
                    "detail": f"Admin endpoint accessible with regular user credentials via {method}",
                })
            # 405 Method Not Allowed means endpoint exists but method is wrong
            elif resp.status_code == 405:
                findings.append({
                    "url": url,
                    "method": method,
                    "status_code": 405,
                    "detail": f"Admin endpoint EXISTS (405) — try different HTTP methods",
                })

        return findings

    async def _test_http_method_override(self) -> List[Dict]:
        """Test HTTP method override via X-HTTP-Method-Override header."""
        findings = []
        test_url = self.config.target_url + "/api/admin/users"

        # Try to DELETE via GET with method override header
        resp = await self.request(
            "GET", test_url,
            extra_headers={"X-HTTP-Method-Override": "DELETE", "X-Method-Override": "DELETE"}
        )
        if resp and resp.status_code in [200, 204]:
            findings.append({
                "url": test_url,
                "technique": "HTTP Method Override",
                "detail": "Server honors X-HTTP-Method-Override header — may bypass function authorization",
            })

        return findings

    async def scan(self) -> Dict[str, Any]:
        all_findings: List[Dict] = []

        # Test all admin paths concurrently
        tasks = [self._test_admin_path(p) for p in self.ADMIN_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)

        # Test HTTP method override
        override_findings = await self._test_http_method_override()
        all_findings.extend(override_findings)

        # Filter to only show actually accessible endpoints
        real_findings = [f for f in all_findings if f.get("status_code") in [200, 201]]

        found = len(real_findings) > 0
        evidence = {
            "accessible_admin_endpoints": real_findings,
            "all_detections": all_findings,
            "paths_tested": len(self.ADMIN_PATHS),
            "test_description": (
                "Tested common admin/management API endpoints using current authentication. "
                "Vulnerability is confirmed when admin endpoints return 200/201 for non-admin users."
            ),
        }
        return self.base_finding(found, evidence)
