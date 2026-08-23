"""
API Security Scanner — FastAPI Backend
Main entry point: handles scan requests, SSE streaming, and results.
"""
import asyncio
import json
import os
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── Path setup ───────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from remediation.engine import RemediationEngine
from scanner.api1_bola import BOLAScanner
from scanner.api10_unsafe_api import UnsafeAPIScanner
from scanner.api2_broken_auth import BrokenAuthScanner
from scanner.api3_mass_assignment import MassAssignmentScanner
from scanner.api4_rate_limit import RateLimitScanner
from scanner.api5_func_auth import FuncAuthScanner
from scanner.api6_business_flow import BusinessFlowScanner
from scanner.api7_ssrf import SSRFScanner
from scanner.api8_misconfiguration import MisconfigScanner
from scanner.api9_inventory import InventoryScanner
from scanner.base import ScanConfig
from scoring.cve_fetcher import CVEFetcher
from scoring.cvss_scorer import CVSSScorer

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(title="API Security Scanner", version="1.0.0", docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

# ── In-memory scan store ──────────────────────────────────────────────────────
scans: Dict[str, Any] = {}

# ── Request models ────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target_url: str
    auth_token: Optional[str] = None
    selected_tests: Optional[List[str]] = None  # e.g. ["API1","API3"] or None = all


# ── Scan runner ───────────────────────────────────────────────────────────────
ALL_SCANNERS = [
    ("API1",  "Broken Object Level Authorization (BOLA)",       BOLAScanner),
    ("API2",  "Broken Authentication",                          BrokenAuthScanner),
    ("API3",  "Broken Object Property Level Authorization",     MassAssignmentScanner),
    ("API4",  "Unrestricted Resource Consumption",              RateLimitScanner),
    ("API5",  "Broken Function Level Authorization",            FuncAuthScanner),
    ("API6",  "Unrestricted Access to Sensitive Business Flows",BusinessFlowScanner),
    ("API7",  "Server Side Request Forgery (SSRF)",             SSRFScanner),
    ("API8",  "Security Misconfiguration",                      MisconfigScanner),
    ("API9",  "Improper Inventory Management",                  InventoryScanner),
    ("API10", "Unsafe Consumption of APIs",                     UnsafeAPIScanner),
]


async def run_scan(scan_id: str, request: ScanRequest) -> None:
    config = ScanConfig(
        target_url=request.target_url.rstrip("/"),
        auth_token=request.auth_token,
    )
    log_q: asyncio.Queue = scans[scan_id]["logs"]
    results: List[Dict] = []

    async def log(msg: str, level: str = "info", vuln_id: str = "") -> None:
        await log_q.put({
            "type": "log",
            "level": level,
            "message": msg,
            "vuln_id": vuln_id,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        })

    scorer = CVSSScorer()
    cve_fetcher = CVEFetcher()
    remediation_engine = RemediationEngine()
    selected = request.selected_tests or [s[0] for s in ALL_SCANNERS]

    await log("🚀 API Security Scanner starting...", "info")
    await log(f"🎯 Target: {config.target_url}", "info")
    await log(f"🔬 Running {len(selected)} test modules", "info")
    await log("─" * 50, "divider")

    for vuln_id, vuln_name, ScannerClass in ALL_SCANNERS:
        if vuln_id not in selected:
            continue

        await log(f"⚡ [{vuln_id}] Testing: {vuln_name}", "info", vuln_id)

        try:
            scanner_instance = ScannerClass(config)
            finding = await scanner_instance.scan()

            # Enrich with CVSS score
            cvss_result = scorer.score(finding.get("cvss_vector", ""))
            finding["cvss_score"] = cvss_result["score"]
            finding["cvss_severity"] = cvss_result["severity"]
            finding["cvss_color"] = cvss_result["color"]

            # Enrich with CVE references
            finding["cve_references"] = await cve_fetcher.fetch(vuln_id)

            # Enrich with remediation
            finding["remediation"] = remediation_engine.get(vuln_id)

            results.append(finding)

            if finding.get("found"):
                await log(
                    f"🔴 VULNERABLE [{vuln_id}]: {vuln_name} — Score: {cvss_result['score']} ({cvss_result['severity']})",
                    "danger", vuln_id
                )
            else:
                await log(f"✅ PASSED [{vuln_id}]: {vuln_name} — No issues detected", "success", vuln_id)

        except Exception as exc:
            await log(f"⚠️  ERROR [{vuln_id}]: {exc}", "warning", vuln_id)
            results.append({
                "vuln_id": vuln_id,
                "name": vuln_name,
                "found": False,
                "error": str(exc),
                "cvss_score": 0.0,
                "cvss_severity": "Unknown",
                "cvss_color": "#94a3b8",
                "cvss_vector": "",
                "evidence": {},
                "cve_references": [],
                "remediation": remediation_engine.get(vuln_id),
            })

    scans[scan_id]["results"] = results
    scans[scan_id]["status"] = "complete"
    scans[scan_id]["completed_at"] = datetime.now().isoformat()

    vulns_found = sum(1 for r in results if r.get("found"))
    await log("─" * 50, "divider")
    await log(
        f"🎯 Scan complete! {vulns_found} vulnerabilit{'y' if vulns_found == 1 else 'ies'} found out of {len(results)} tests.",
        "complete"
    )
    await log_q.put({"type": "complete", "results": results})


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/")
async def serve_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "API Security Scanner — Frontend not found. Run from project root."}


@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if not request.target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="target_url must start with http:// or https://")

    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        "status": "running",
        "logs": asyncio.Queue(),
        "results": [],
        "started_at": datetime.now().isoformat(),
        "target": request.target_url,
    }
    background_tasks.add_task(run_scan, scan_id, request)
    return {"scan_id": scan_id, "status": "running", "started_at": scans[scan_id]["started_at"]}


@app.get("/api/scan/{scan_id}/stream")
async def stream_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_gen():
        while True:
            try:
                msg = await asyncio.wait_for(scans[scan_id]["logs"].get(), timeout=30.0)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get("type") == "complete":
                    break
            except asyncio.TimeoutError:
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@app.get("/api/scan/{scan_id}/results")
async def get_results(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]
    return {
        "scan_id": scan_id,
        "status": scan["status"],
        "target": scan["target"],
        "started_at": scan["started_at"],
        "completed_at": scan.get("completed_at"),
        "results": scan["results"],
        "summary": {
            "total": len(scan["results"]),
            "vulnerable": sum(1 for r in scan["results"] if r.get("found")),
            "critical": sum(1 for r in scan["results"] if r.get("cvss_severity") == "Critical" and r.get("found")),
            "high": sum(1 for r in scan["results"] if r.get("cvss_severity") == "High" and r.get("found")),
            "medium": sum(1 for r in scan["results"] if r.get("cvss_severity") == "Medium" and r.get("found")),
            "low": sum(1 for r in scan["results"] if r.get("cvss_severity") == "Low" and r.get("found")),
        },
    }


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
