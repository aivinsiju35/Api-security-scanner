"""
Remediation Engine
Loads the knowledge base and provides remediation data for each vulnerability.
"""
import json
import os
from typing import Dict, Any


class RemediationEngine:
    def __init__(self):
        kb_path = os.path.join(os.path.dirname(__file__), "knowledge_base.json")
        with open(kb_path, "r", encoding="utf-8") as f:
            self._kb: Dict[str, Any] = json.load(f)

    def get(self, vuln_id: str) -> Dict[str, Any]:
        """Return full remediation data for a given OWASP category."""
        entry = self._kb.get(vuln_id, {})
        return {
            "owasp_id": entry.get("owasp_id", ""),
            "description": entry.get("description", ""),
            "impact": entry.get("impact", ""),
            "owasp_url": entry.get("owasp_url", ""),
            "summary": entry.get("remediation", {}).get("summary", ""),
            "steps": entry.get("remediation", {}).get("steps", []),
            "code_example": entry.get("remediation", {}).get("code_example", {}),
            "references": entry.get("remediation", {}).get("references", []),
        }

    def get_all(self) -> Dict[str, Any]:
        """Return all remediation data."""
        return {vid: self.get(vid) for vid in self._kb}
