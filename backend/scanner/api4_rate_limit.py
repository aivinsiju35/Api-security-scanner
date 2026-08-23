"""
API4:2023 - Unrestricted Resource Consumption
Tests for missing rate limiting, no throttling on expensive operations,
and lack of request size limits.
"""
from .base import BaseScanner, ScanConfig
from typing import Dict, Any, List
import asyncio
import time


class RateLimitScanner(BaseScanner):
    VULN_ID = "API4"
    VULN_NAME = "Unrestricted Resource Consumption"
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"

    TEST_PATHS = [
        "/api/v1/users",
        "/api/users",
        "/api/v1/products",
        "/api/products",
        "/api/v1/posts",
        "/",
    ]

    RAPID_REQUEST_COUNT = 20

    async def _test_rate_limit(self, path: str) -> Dict:
        url = self.config.target_url + path
        statuses: List[int] = []
        times: List[float] = []

        # Send rapid burst of requests
        start = time.time()
        tasks = [self.request("GET", url) for _ in range(self.RAPID_REQUEST_COUNT)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start

        for r in responses:
            if isinstance(r, Exception) or r is None:
                continue
            statuses.append(r.status_code)

        if not statuses:
            return {"url": url, "tested": False}

        rate_limited = any(s == 429 for s in statuses)
        return {
            "url": url,
            "tested": True,
            "total_requests": len(statuses),
            "rate_limited": rate_limited,
            "status_codes": list(set(statuses)),
            "elapsed_seconds": round(elapsed, 2),
            "requests_per_second": round(len(statuses) / elapsed, 1) if elapsed > 0 else 0,
            "vulnerable": not rate_limited and len(statuses) >= 10,
        }

    async def _test_large_payload(self) -> Dict:
        """Test if API accepts excessively large payloads."""
        vulnerable_paths = []
        for path in ["/api/v1/users", "/api/users", "/api/search"]:
            url = self.config.target_url + path
            # Send a large payload (50KB of data)
            large_data = {"data": "A" * 50000, "query": "B" * 10000}
            resp = await self.request("POST", url, json=large_data)
            if resp and resp.status_code not in [413, 400, 422]:
                vulnerable_paths.append(url)
        return {"vulnerable_paths": vulnerable_paths}

    async def scan(self) -> Dict[str, Any]:
        issues = []

        # Test rate limiting on multiple paths
        tasks = [self._test_rate_limit(p) for p in self.TEST_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        no_rate_limit_endpoints = []
        for r in results:
            if isinstance(r, dict) and r.get("tested") and r.get("vulnerable"):
                no_rate_limit_endpoints.append({
                    "url": r["url"],
                    "requests_sent": r["total_requests"],
                    "requests_per_second": r["requests_per_second"],
                    "status_codes": r["status_codes"],
                })

        if no_rate_limit_endpoints:
            issues.append({
                "type": "no_rate_limiting",
                "endpoints": no_rate_limit_endpoints,
                "detail": f"Sent {self.RAPID_REQUEST_COUNT} rapid requests with no 429 rate-limit response",
            })

        # Test large payload acceptance
        payload_result = await self._test_large_payload()
        if payload_result["vulnerable_paths"]:
            issues.append({
                "type": "large_payload_accepted",
                "urls": payload_result["vulnerable_paths"],
                "detail": "API accepts extremely large payloads (50KB+) without returning 413",
            })

        found = len(issues) > 0
        evidence = {
            "issues_found": issues,
            "test_description": (
                f"Sent {self.RAPID_REQUEST_COUNT} concurrent requests to each endpoint. "
                "Rate limiting is detected by 429 (Too Many Requests) responses. "
                "Also tested for large payload acceptance."
            ),
        }
        return self.base_finding(found, evidence)
