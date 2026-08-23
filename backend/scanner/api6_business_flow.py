"""
API6:2023 - Unrestricted Access to Sensitive Business Flows
Tests whether business-critical operations are protected from automated abuse
(e.g., mass coupon redemption, OTP brute-force, inventory manipulation).
"""
from .base import BaseScanner, ScanConfig
from typing import Dict, Any, List
import asyncio


class BusinessFlowScanner(BaseScanner):
    VULN_ID = "API6"
    VULN_NAME = "Unrestricted Access to Sensitive Business Flows"
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"

    BUSINESS_PATHS = [
        ("/api/v1/coupon/apply", "POST", {"coupon_code": "DISCOUNT50"}, "Coupon Application"),
        ("/api/coupon/apply", "POST", {"coupon_code": "DISCOUNT50"}, "Coupon Application"),
        ("/api/v1/otp/verify", "POST", {"otp": "1234"}, "OTP Verification"),
        ("/api/otp/verify", "POST", {"otp": "1234"}, "OTP Verification"),
        ("/api/v1/checkout", "POST", {"quantity": 1000}, "Checkout"),
        ("/api/checkout", "POST", {"quantity": 1000}, "Checkout"),
        ("/api/v1/password/reset", "POST", {"email": "test@test.com"}, "Password Reset"),
        ("/api/password-reset", "POST", {"email": "test@test.com"}, "Password Reset"),
        ("/api/v1/referral", "POST", {"code": "REF123"}, "Referral"),
        ("/api/v1/vote", "POST", {"item_id": 1}, "Voting"),
    ]

    ABUSE_COUNT = 10  # Number of rapid attempts

    async def _test_business_flow(self, path: str, method: str, payload: dict, name: str) -> Dict:
        url = self.config.target_url + path
        statuses: List[int] = []

        # Send multiple rapid requests to simulate abuse
        tasks = [self.request(method, url, json=payload) for _ in range(self.ABUSE_COUNT)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for r in responses:
            if isinstance(r, Exception) or r is None:
                continue
            statuses.append(r.status_code)

        if not statuses:
            return {}

        # Check if any 429/403/blocked responses
        protected = any(s in [429, 423, 403] for s in statuses)
        success_count = sum(1 for s in statuses if s in [200, 201, 204])

        return {
            "name": name,
            "url": url,
            "method": method,
            "attempts": len(statuses),
            "success_count": success_count,
            "rate_limited": protected,
            "status_codes": list(set(statuses)),
            "vulnerable": not protected and success_count >= 2,
        }

    async def scan(self) -> Dict[str, Any]:
        all_issues: List[Dict] = []

        tasks = [self._test_business_flow(p, m, pay, name) for p, m, pay, name in self.BUSINESS_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, dict) and r.get("vulnerable"):
                all_issues.append({
                    "flow_name": r["name"],
                    "url": r["url"],
                    "successful_attempts": r["success_count"],
                    "total_attempts": r["attempts"],
                    "detail": (
                        f"Business flow '{r['name']}' can be abused: "
                        f"{r['success_count']}/{r['attempts']} requests succeeded without rate limiting"
                    ),
                })

        found = len(all_issues) > 0
        evidence = {
            "abusable_flows": all_issues,
            "test_description": (
                f"Sent {self.ABUSE_COUNT} rapid requests to each business-critical endpoint. "
                "Vulnerable if multiple requests succeed without 429/423 blocking."
            ),
        }
        return self.base_finding(found, evidence)
