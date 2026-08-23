"""
API1:2023 - Broken Object Level Authorization (BOLA / IDOR)
Tests whether an API allows access to resources belonging to other users
by manipulating object IDs in the URL path or query parameters.
"""
from .base import BaseScanner, ScanConfig
from typing import Dict, Any, List
import asyncio


class BOLAScanner(BaseScanner):
    VULN_ID = "API1"
    VULN_NAME = "Broken Object Level Authorization (BOLA)"
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"

    # Common endpoint patterns that typically carry object IDs
    ID_PATTERNS = [
        "/api/v1/users/{id}",
        "/api/v2/users/{id}",
        "/api/users/{id}",
        "/api/v1/orders/{id}",
        "/api/orders/{id}",
        "/api/v1/posts/{id}",
        "/api/posts/{id}",
        "/api/v1/items/{id}",
        "/api/items/{id}",
        "/api/v1/accounts/{id}",
        "/users/{id}",
        "/orders/{id}",
    ]

    async def _try_endpoint(self, pattern: str, obj_id: int) -> Dict:
        url = self.config.target_url + pattern.replace("{id}", str(obj_id))
        resp = await self.request("GET", url)
        if resp is None:
            return {"url": url, "status": None, "accessible": False}
        return {
            "url": url,
            "status": resp.status_code,
            "accessible": resp.status_code == 200,
            "body_size": len(resp.content),
        }

    async def scan(self) -> Dict[str, Any]:
        # Try to detect accessible endpoints with different IDs
        findings: List[Dict] = []
        vulnerable_endpoints: List[Dict] = []

        # Test a few ID patterns across the target
        tasks = []
        for pattern in self.ID_PATTERNS[:6]:  # Limit to 6 patterns for speed
            for obj_id in [1, 2, 3]:
                tasks.append(self._try_endpoint(pattern, obj_id))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Group results by pattern
        pattern_hits: Dict[str, List] = {}
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                continue
            pattern = self.ID_PATTERNS[i // 3]
            if pattern not in pattern_hits:
                pattern_hits[pattern] = []
            pattern_hits[pattern].append(result)

        # A pattern is BOLA-vulnerable if multiple IDs return 200
        for pattern, hits in pattern_hits.items():
            accessible = [h for h in hits if h.get("accessible")]
            if len(accessible) >= 2:
                vulnerable_endpoints.append({
                    "pattern": pattern,
                    "accessible_ids": [h["url"] for h in accessible],
                    "status_codes": [h["status"] for h in accessible],
                })

        # Also check if unauthenticated access works on any endpoint
        # by sending request without auth token
        unauth_hits = []
        for pattern in self.ID_PATTERNS[:4]:
            url = self.config.target_url + pattern.replace("{id}", "1")
            resp = await self.request("GET", url, no_auth=True)
            if resp and resp.status_code == 200:
                unauth_hits.append(url)

        found = len(vulnerable_endpoints) > 0 or len(unauth_hits) > 0

        evidence = {
            "vulnerable_endpoints": vulnerable_endpoints,
            "unauthenticated_access": unauth_hits,
            "test_description": (
                "Tested multiple object IDs on common endpoint patterns. "
                "BOLA is detected when different IDs return 200 without proper authorization checks, "
                "or when endpoints are accessible without authentication."
            ),
        }

        return self.base_finding(found, evidence)
