"""
CVSS v3.1 Scorer
Uses the 'cvss' library to parse CVSS vectors and calculate base scores.
Falls back to a manual lookup table if the library is unavailable.
"""
from typing import Dict

try:
    from cvss import CVSS3
    CVSS_AVAILABLE = True
except ImportError:
    CVSS_AVAILABLE = False

# Fallback score table per OWASP API Top 10 vulnerability
FALLBACK_SCORES = {
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N": (8.1, "High"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": (9.8, "Critical"),
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N": (7.1, "High"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": (7.5, "High"),
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": (8.8, "High"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N": (7.5, "High"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N": (10.0, "Critical"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L": (8.6, "High"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N": (8.2, "High"),
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N": (7.4, "High"),
}

SEVERITY_COLORS = {
    "Critical": "#ef4444",
    "High": "#f97316",
    "Medium": "#eab308",
    "Low": "#22c55e",
    "None": "#94a3b8",
}


class CVSSScorer:
    def score(self, cvss_vector: str) -> Dict:
        """
        Calculate CVSS v3.1 base score from a vector string.
        Returns a dict with score, severity, and color.
        """
        if not cvss_vector:
            return {"score": 0.0, "severity": "None", "color": SEVERITY_COLORS["None"], "vector": ""}

        # Try library first
        if CVSS_AVAILABLE:
            try:
                c = CVSS3(cvss_vector)
                score = float(c.base_score)
                severity = self._severity_from_score(score)
                return {
                    "score": score,
                    "severity": severity,
                    "color": SEVERITY_COLORS.get(severity, "#94a3b8"),
                    "vector": cvss_vector,
                }
            except Exception:
                pass

        # Fallback to lookup table
        if cvss_vector in FALLBACK_SCORES:
            score, severity = FALLBACK_SCORES[cvss_vector]
            return {
                "score": score,
                "severity": severity,
                "color": SEVERITY_COLORS.get(severity, "#94a3b8"),
                "vector": cvss_vector,
            }

        # Last resort: parse AV/C/I/A manually
        score = self._manual_score(cvss_vector)
        severity = self._severity_from_score(score)
        return {
            "score": score,
            "severity": severity,
            "color": SEVERITY_COLORS.get(severity, "#94a3b8"),
            "vector": cvss_vector,
        }

    def _severity_from_score(self, score: float) -> str:
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0:
            return "Low"
        return "None"

    def _manual_score(self, vector: str) -> float:
        """Very rough score estimation from vector components."""
        score = 5.0
        if "AV:N" in vector:
            score += 1.5
        if "PR:N" in vector:
            score += 1.0
        if "C:H" in vector:
            score += 0.5
        if "I:H" in vector:
            score += 0.5
        if "A:H" in vector:
            score += 0.5
        if "S:C" in vector:
            score += 1.0
        return min(round(score, 1), 10.0)
