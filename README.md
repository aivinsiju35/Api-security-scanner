# API Security Scanner

A full-stack web application for testing APIs against all **OWASP API Top 10 (2023)** vulnerabilities, with CVSS v3.1 scoring, CVE references, and detailed remediation guidance.

---

## 🚀 Quick Start

### Option 1 — Double-click (Windows)
```
Double-click: start.bat
```
Then open your browser to: **http://localhost:8000**

### Option 2 — Manual

**1. Install dependencies:**
```bash
cd backend
python -m pip install fastapi "uvicorn[standard]" httpx cvss python-multipart aiofiles
```

**2. Start the server:**
```bash
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**3. Open browser:**
```
http://localhost:8000
```

---

## 🎯 Features

| Feature | Details |
|---|---|
| **OWASP API Top 10** | All 10 vulnerability tests (API1–API10) |
| **CVSS v3.1 Scoring** | Automatic score calculation per finding |
| **CVE References** | Real CVEs fetched from NVD database |
| **Remediation** | Step-by-step fixes + secure code examples |
| **Live Log** | Real-time terminal output during scan |
| **Severity Chart** | Visual distribution of vulnerabilities |
| **Export** | Download full report as JSON |

---

## 🧪 Test Target

For safe testing, use a deliberately vulnerable API:

### OWASP crAPI (Recommended)
```bash
# Requires Docker
docker pull levoai/crapi:latest
docker run -d -p 8888:8888 levoai/crapi:latest
# Then scan: http://localhost:8888
```

### DVAPI
```
https://github.com/payatu/DVAPI
```

---

## 📁 Project Structure

```
api-security-scanner/
├── backend/
│   ├── main.py                    # FastAPI server
│   ├── scanner/
│   │   ├── api1_bola.py           # BOLA tester
│   │   ├── api2_broken_auth.py    # Auth tester
│   │   ├── api3_mass_assignment.py
│   │   ├── api4_rate_limit.py
│   │   ├── api5_func_auth.py
│   │   ├── api6_business_flow.py
│   │   ├── api7_ssrf.py
│   │   ├── api8_misconfiguration.py
│   │   ├── api9_inventory.py
│   │   └── api10_unsafe_api.py
│   ├── scoring/
│   │   ├── cvss_scorer.py         # CVSS v3.1
│   │   └── cve_fetcher.py         # NVD API
│   └── remediation/
│       ├── engine.py
│       └── knowledge_base.json    # Full remediation DB
├── frontend/
│   ├── index.html
│   ├── css/style.css
│   └── js/app.js
├── start.bat                      # Windows quick start
└── README.md
```

---

## ⚠️ Legal Notice

Only scan APIs you own or have explicit written permission to test.
Unauthorized security testing is illegal.
