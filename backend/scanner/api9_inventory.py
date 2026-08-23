"""
API9:2023 - Improper Inventory Management
Tests for undocumented/deprecated API versions still accessible,
and hidden endpoints that should have been retired.
"""
from .base import BaseScanner, ScanConfig
from typing import Dict, Any, List
import asyncio


class InventoryScanner(BaseScanner):
    VULN_ID = "API9"
    VULN_NAME = "Improper Inventory Management"
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"

    # Old/deprecated API version prefixes to test
    OLD_VERSIONS = ["v1", "v2", "v3", "v0", "beta", "alpha", "old", "legacy", "test", "dev"]

    # Common deprecated endpoint patterns
    DEPRECATED_PATHS = [
        "/api/{ver}/users",
        "/api/{ver}/auth/login",
        "/api/{ver}/products",
        "/api/{ver}/admin",
        "/{ver}/api/users",
        "/{ver}/users",
    ]

    # Common hidden/forgotten endpoints
    HIDDEN_PATHS = [
        "/api/v1/users/export",
        "/api/export",
        "/api/v1/dump",
        "/api/dump",
        "/api/v1/backup",
        "/api/backup",
        "/api/v2/internal",
        "/api/internal/users",
        "/api/test/users",
        "/api/dev/users",
        "/api/v1/graphql",
        "/graphql",
        "/api/v1/migration",
        "/api/private",
    ]

    async def _test_old_version(self, version: str, path_template: str) -> Dict:
        path = path_template.replace("{ver}", version)
        url = self.config.target_url + path
        resp = await self.request("GET", url)
        if resp is None:
            return {}
        return {
            "version": version,
            "url": url,
            "status": resp.status_code,
            "accessible": resp.status_code in [200, 201, 301, 302],
        }

    async def _test_hidden_path(self, path: str) -> Dict:
        url = self.config.target_url + path
        resp = await self.request("GET", url)
        if resp is None:
            return {}
        return {
            "url": url,
            "status": resp.status_code,
            "accessible": resp.status_code in [200, 201],
            "body_size": len(resp.content) if resp else 0,
        }

    async def scan(self) -> Dict[str, Any]:
        accessible_old_versions: List[Dict] = []
        accessible_hidden: List[Dict] = []

        # Test old/deprecated API versions
        version_tasks = []
        for version in self.OLD_VERSIONS:
            for path_template in self.DEPRECATED_PATHS[:3]:
                version_tasks.append(self._test_old_version(version, path_template))

        version_results = await asyncio.gather(*version_tasks, return_exceptions=True)
        for r in version_results:
            if isinstance(r, dict) and r.get("accessible"):
                # Only include if not the "current" detected version
                accessible_old_versions.append(r)

        # Test hidden/forgotten endpoints
        hidden_tasks = [self._test_hidden_path(p) for p in self.HIDDEN_PATHS]
        hidden_results = await asyncio.gather(*hidden_tasks, return_exceptions=True)
        for r in hidden_results:
            if isinstance(r, dict) and r.get("accessible"):
                accessible_hidden.append(r)

        # Deduplicate
        seen_urls = set()
        unique_old = []
        for r in accessible_old_versions:
            if r["url"] not in seen_urls:
                seen_urls.add(r["url"])
                unique_old.append(r)

        found = len(unique_old) > 0 or len(accessible_hidden) > 0

        evidence = {
            "deprecated_versions_accessible": unique_old[:10],
            "hidden_endpoints_accessible": accessible_hidden,
            "old_versions_tested": self.OLD_VERSIONS,
            "test_description": (
                "Probed for deprecated/old API versions (v0, v1, beta, dev, legacy) "
                "and hidden/forgotten endpoints (export, dump, backup, internal). "
                "Old API versions often lack security controls applied to newer versions."
            ),
        }
        return self.base_finding(found, evidence)
