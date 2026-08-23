import httpx
from typing import Optional, Dict, Any
from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    target_url: str
    auth_token: Optional[str] = None
    timeout: int = 10

    @property
    def headers(self) -> Dict[str, str]:
        h = {
            "Content-Type": "application/json",
            "User-Agent": "API-Security-Scanner/1.0",
            "Accept": "application/json",
        }
        if self.auth_token:
            h["Authorization"] = f"Bearer {self.auth_token}"
        return h


class BaseScanner:
    VULN_ID: str = ""
    VULN_NAME: str = ""
    CVSS_VECTOR: str = ""

    def __init__(self, config: ScanConfig):
        self.config = config

    async def request(
        self,
        method: str,
        url: str,
        extra_headers: Optional[Dict] = None,
        no_auth: bool = False,
        **kwargs,
    ) -> Optional[httpx.Response]:
        headers = self.config.headers.copy()
        if no_auth:
            headers.pop("Authorization", None)
        if extra_headers:
            headers.update(extra_headers)
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.config.timeout, follow_redirects=True) as client:
                return await client.request(method, url, headers=headers, **kwargs)
        except Exception:
            return None

    def base_finding(self, found: bool, evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "vuln_id": self.VULN_ID,
            "name": self.VULN_NAME,
            "found": found,
            "cvss_vector": self.CVSS_VECTOR,
            "evidence": evidence or {},
            "severity": "",
            "cvss_score": 0.0,
            "cve_references": [],
            "remediation": {},
        }

    async def scan(self) -> Dict[str, Any]:
        raise NotImplementedError
