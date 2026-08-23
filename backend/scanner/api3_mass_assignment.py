"""
API3:2023 - Broken Object Property Level Authorization
Tests for mass assignment (accepting extra/admin fields) and
excessive data exposure (returning more data than needed).
"""
from .base import BaseScanner, ScanConfig
from typing import Dict, Any, List
import asyncio


class MassAssignmentScanner(BaseScanner):
    VULN_ID = "API3"
    VULN_NAME = "Broken Object Property Level Authorization"
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N"

    CREATE_PATHS = [
        "/api/v1/users",
        "/api/users",
        "/api/v1/register",
        "/api/register",
        "/api/auth/register",
        "/api/v1/profile",
    ]

    # Privileged fields that should never be accepted from client
    PRIVILEGED_FIELDS = ["isAdmin", "is_admin", "role", "admin", "verified", "balance", "credits", "premium"]

    SENSITIVE_FIELD_PATTERNS = [
        "password", "password_hash", "secret", "api_key", "token",
        "ssn", "credit_card", "card_number", "cvv", "private_key"
    ]

    async def _test_mass_assignment(self, path: str) -> List[Dict]:
        url = self.config.target_url + path
        issues = []

        # Send a POST request with privileged fields embedded
        payload = {
            "username": "testuser_scanner",
            "email": "scanner_test@example.com",
            "password": "Test@12345",
            "name": "Scanner Test",
            # Privileged fields
            "isAdmin": True,
            "is_admin": True,
            "role": "admin",
            "verified": True,
            "balance": 99999,
        }

        resp = await self.request("POST", url, json=payload)
        if resp is None:
            return issues

        if resp.status_code in [200, 201]:
            try:
                data = resp.json()
                # Check if any privileged fields were reflected back
                reflected = []
                for f in self.PRIVILEGED_FIELDS:
                    if f in data and data[f] in [True, "admin", 99999]:
                        reflected.append(f)
                if reflected:
                    issues.append({
                        "type": "mass_assignment",
                        "url": url,
                        "reflected_fields": reflected,
                        "detail": f"API accepted and reflected privileged fields: {', '.join(reflected)}",
                    })
            except Exception:
                pass

        return issues

    async def _test_excessive_exposure(self, path: str) -> List[Dict]:
        url = self.config.target_url + path
        issues = []
        resp = await self.request("GET", url)
        if resp is None:
            return issues

        if resp.status_code == 200:
            try:
                body = resp.text.lower()
                exposed = []
                for field in self.SENSITIVE_FIELD_PATTERNS:
                    if f'"{field}"' in body or f"'{field}'" in body:
                        exposed.append(field)
                if exposed:
                    issues.append({
                        "type": "excessive_data_exposure",
                        "url": url,
                        "exposed_fields": exposed,
                        "detail": f"Response may contain sensitive fields: {', '.join(exposed)}",
                    })
            except Exception:
                pass

        return issues

    async def scan(self) -> Dict[str, Any]:
        all_issues: List[Dict] = []

        # Test mass assignment on create endpoints
        create_tasks = [self._test_mass_assignment(p) for p in self.CREATE_PATHS[:4]]
        results = await asyncio.gather(*create_tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                all_issues.extend(r)

        # Test excessive data exposure on GET endpoints
        get_paths = ["/api/v1/users", "/api/users", "/api/v1/profile", "/api/profile"]
        exposure_tasks = [self._test_excessive_exposure(p) for p in get_paths]
        exp_results = await asyncio.gather(*exposure_tasks, return_exceptions=True)
        for r in exp_results:
            if isinstance(r, list):
                all_issues.extend(r)

        found = len(all_issues) > 0
        evidence = {
            "issues_found": all_issues,
            "test_description": (
                "Tested for mass assignment by sending privileged fields (isAdmin, role, balance) "
                "in POST requests and checking if they are reflected in responses. "
                "Also checked GET responses for sensitive field exposure."
            ),
        }
        return self.base_finding(found, evidence)
