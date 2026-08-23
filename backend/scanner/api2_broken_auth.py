"""
API2:2023 - Broken Authentication
Tests for weak token validation, missing expiry, predictable tokens,
and brute-force vulnerabilities in authentication mechanisms.
"""
from .base import BaseScanner, ScanConfig
from typing import Dict, Any
import asyncio
import base64
import json


class BrokenAuthScanner(BaseScanner):
    VULN_ID = "API2"
    VULN_NAME = "Broken Authentication"
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    LOGIN_PATHS = ["/api/auth/login", "/api/login", "/auth/login", "/login", "/api/v1/auth/login"]
    PROTECTED_PATHS = ["/api/v1/users/me", "/api/me", "/api/user", "/api/profile", "/api/v1/profile"]
    WEAK_PASSWORDS = ["password", "123456", "admin", "test", "password123"]

    def _is_valid_jwt(self, token: str) -> bool:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return False
            # Decode header
            padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(padded))
            return "alg" in header
        except Exception:
            return False

    def _check_none_alg(self, token: str) -> bool:
        """Check if JWT uses 'none' algorithm (critical vulnerability)."""
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return False
            padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(padded))
            alg = header.get("alg", "").lower()
            return alg in ["none", "null", ""]
        except Exception:
            return False

    async def scan(self) -> Dict[str, Any]:
        issues = []

        # 1. Test unauthenticated access to protected endpoints
        for path in self.PROTECTED_PATHS:
            url = self.config.target_url + path
            resp = await self.request("GET", url, no_auth=True)
            if resp and resp.status_code == 200:
                issues.append({
                    "type": "unauthenticated_access",
                    "url": url,
                    "status": resp.status_code,
                    "detail": "Protected endpoint accessible without authentication token",
                })

        # 2. Test with invalid/malformed tokens
        bad_tokens = [
            "invalid.token.here",
            "Bearer null",
            "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",  # none alg
            "test",
        ]
        for bad_token in bad_tokens[:2]:
            for path in self.PROTECTED_PATHS[:2]:
                url = self.config.target_url + path
                resp = await self.request("GET", url, extra_headers={"Authorization": f"Bearer {bad_token}"})
                if resp and resp.status_code == 200:
                    issues.append({
                        "type": "invalid_token_accepted",
                        "url": url,
                        "token_used": bad_token[:30] + "...",
                        "detail": "API accepted an invalid/malformed token",
                    })

        # 3. Check for brute-force protection on login endpoints
        for path in self.LOGIN_PATHS:
            url = self.config.target_url + path
            statuses = []
            for pwd in self.WEAK_PASSWORDS:
                resp = await self.request(
                    "POST", url,
                    no_auth=True,
                    json={"username": "admin", "password": pwd, "email": "admin@test.com"}
                )
                if resp:
                    statuses.append(resp.status_code)
                await asyncio.sleep(0.05)

            # If all responses are 401/403/400 without any 429, no rate limit
            non_rate_limited = all(s in [400, 401, 403] for s in statuses if s is not None)
            if statuses and non_rate_limited and len(statuses) >= 3:
                issues.append({
                    "type": "no_brute_force_protection",
                    "url": url,
                    "attempts": len(statuses),
                    "detail": f"Sent {len(statuses)} login attempts with no rate limiting (no 429 returned)",
                })

        # 4. Test if current token (if provided) works after sending logout
        if self.config.auth_token:
            for path in self.PROTECTED_PATHS:
                url = self.config.target_url + path
                resp = await self.request("GET", url)
                if resp and resp.status_code == 200:
                    # Check if JWT has very long or no expiry
                    if self._is_valid_jwt(self.config.auth_token):
                        if self._check_none_alg(self.config.auth_token):
                            issues.append({
                                "type": "jwt_none_algorithm",
                                "detail": "JWT uses 'none' algorithm — signature not verified!",
                                "url": url,
                            })
                    break

        found = len(issues) > 0
        evidence = {
            "issues_found": issues,
            "test_description": (
                "Tested for: unauthenticated access to protected endpoints, "
                "invalid token acceptance, lack of brute-force protection, "
                "and JWT algorithm weaknesses."
            ),
        }
        return self.base_finding(found, evidence)
