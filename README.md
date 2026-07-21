#  IOC Enrichment and Automated Triage Platform v2.0

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **A production-grade SOC automation tool that ingests Indicators of Compromise (IOCs), queries multiple threat intelligence APIs concurrently, and generates structured triage reports with severity scoring, score transparency, and SQLite case management.**

##  What Makes This Different

This isn't just a script — it's a **mini SOAR platform** that demonstrates enterprise-level security automation concepts:

| Feature | v1 (Basic) | v2 (This Version) |
|---------|-----------|-------------------|
| API Calls | Sequential (6s/IOC) | **Concurrent** (~2s/IOC) |
| Rate Limiting | None | **Token bucket + exponential backoff** |
| Retry Logic | None | **3 attempts with jitter** |
| IOC Deduplication | None | **Automatic before enrichment** |
| Caching | None | **24h file-based cache** |
| Confidence | Hardcoded | **Derived from source agreement** |
| Score Transparency | Single number | **Full point attribution** |
| Progress Tracking | None | **tqdm progress bars** |
| Report Sorting | Input order | **By severity (Critical first)** |
| Case Management | None | **SQLite with audit trail** |
| Reports | JSON only | **JSON + Markdown + CSV** |

## Architecture

```
ioc-triage-platform/
├── config/
│   └── config.py              # Environment & API configuration
├── input/
│   └── iocs.csv               # IOC input file
├── reports/                   # Generated triage reports
├── src/
│   ├── main.py                # Orchestration engine & CLI
│   ├── virustotal.py          # VT API v3 client with rate limiting
│   ├── abuseipdb.py           # AbuseIPDB API v2 client
│   ├── shodan_lookup.py       # Shodan API client
│   ├── scoring.py             # Multi-source scoring with transparency
│   ├── report_generator.py    # JSON/MD/CSV report generation
│   ├── case_manager.py        # SQLite case management system
│   ├── rate_limiter.py        # Token bucket + retry logic
│   └── utils.py               # IOC classification, dedup, cache
├── tests/                     # Unit tests
├── requirements.txt
├── .env.example
└── README.md
```

##  Quick Start

### Prerequisites
- Python 3.11+
- API keys for [VirusTotal](https://www.virustotal.com/gui/join-us), [AbuseIPDB](https://www.abuseipdb.com/register), and [Shodan](https://account.shodan.io/register)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ioc-triage-platform.git
cd ioc-triage-platform

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt

# Optional: Install tqdm for progress bars
pip install tqdm
```

### Configuration

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your API keys
nano .env
```

```env
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key
```

### Usage

```bash
# Basic run
python src/main.py -i input/iocs.csv

# Generate only JSON and CSV
python src/main.py -i input/iocs.csv --formats json csv

# Skip private IPs, use 3 concurrent workers
python src/main.py -i input/iocs.csv --skip-private --workers 3

# Disable case management
python src/main.py -i input/iocs.csv --no-cases

# Validate configuration
python src/main.py --validate

# Clear API cache
python src/main.py --clear-cache
```

##  Performance: Concurrent vs Sequential

| IOCs | Sequential | Concurrent | Speedup |
|------|-----------|------------|---------|
| 10 | ~60s | ~20s | **3x** |
| 50 | ~300s | ~100s | **3x** |
| 100 | ~600s | ~200s | **3x** |

*Based on 2s average API response time per source*

##  Scoring Methodology

### Weighted Composite Algorithm

| Source | Weight | Metrics |
|--------|--------|---------|
| VirusTotal | 40% | Detection ratio, engine count, reputation |
| AbuseIPDB | 40% | Abuse confidence, report volume, categories |
| Shodan | 20% | Exposed ports, CVEs, risk indicators |

### Score Transparency

Instead of just showing `Score: 92`, the report shows:

```
Score: 92/100

Score Breakdown:
  VirusTotal: 85.0 × 40% = 34.0
    + High detection ratio ≥50% (+50 pts)
    + High engine coverage ≥60 (+10 pts)
    + Negative reputation -12 (+24 pts)
  AbuseIPDB: 95.0 × 40% = 38.0
    + Abuse confidence 100% (+60 pts)
    + Report volume ≥50 (+15 pts)
    + TOR exit node (+10 pts)
  Shodan: 82.0 × 20% = 16.4
    + High-risk ports exposed (+15 pts)
    + CVEs found (3) (+5 pts)

Total: 92.0
```

### Confidence Derivation

Confidence is **derived**, not hardcoded:

| Sources with Data | Confidence | Reasoning |
|-------------------|------------|-----------|
| 3+ (with ≥50 VT engines) | High | Strong multi-source agreement |
| 2 | Medium | Partial corroboration |
| 1 | Low | Single source, limited trust |

### Severity Thresholds

| Score | Severity | Action |
|-------|----------|--------|
| 80-100 | 🔴 Critical | Block immediately, escalate to IR |
| 60-79 | 🟠 High | Investigate urgently, consider containment |
| 40-59 | 🟡 Medium | Monitor closely, scheduled review |
| 20-39 | 🟢 Low | Informational, routine monitoring |
| 0-19 | ⚪ Informational | No action required |

## 🗄️ Case Management

The SQLite case management system mirrors real SOC workflows:

```
Alert Generated
    ↓
IOC Extracted
    ↓
Enrichment (VT + AbuseIPDB + Shodan)
    ↓
Risk Scoring
    ↓
CASE CREATED → CASE-20260721-0001
    ↓
Status: Open
Assigned: Unassigned
Recommendation: Block at firewall
Evidence: [Full enrichment data]
    ↓
Analyst Investigation
    ↓
Status: In Progress → Closed/Escalated
```

### Case Operations

```python
from src.case_manager import CaseManager

cm = CaseManager()

# List open cases
open_cases = cm.list_cases(status="Open")

# Assign to analyst
cm.assign_case("CASE-20260721-0001", "analyst@company.com")

# Add investigation notes
cm.add_note("CASE-20260721-0001", "Confirmed malicious C2 activity")

# Update status
cm.update_status("CASE-20260721-0001", "Escalated", notes="Escalated to IR team")

# Get full timeline
timeline = cm.get_timeline("CASE-20260721-0001")

# Get statistics
stats = cm.get_stats()
```

##  Sample Output

### Console Output

```
 TRIAGE COMPLETE
======================================================================
  🔴 Critical: 2
  🟠 High: 3
  🟡 Medium: 1
  🟢 Low: 2
  ⚪ Informational: 2

  ⚠️  Require Immediate Action: 5
  📁 Cases Created: 5 open

  📄 Reports Generated:
     • triage_report_20260721_143022.json
     • triage_report_20260721_143022.md
     • triage_report_20260721_143022.csv

  💾 Cache Stats: 7 entries
======================================================================
```

### JSON Report (excerpt)

```json
{
  "ioc": "185.220.101.1",
  "type": "ip",
  "score": 87.5,
  "severity": "Critical",
  "confidence": "High",
  "recommendation": "BLOCK IMMEDIATELY - Escalate to incident response",
  "reasons": [
    "High VT detection: 65.2% (42/64 engines)",
    "Very high abuse confidence: 100%",
    "High report volume: 127 reports",
    "TOR exit node detected",
    "High-risk ports exposed: [22, 3389]"
  ],
  "score_breakdown": [
    {
      "source": "VirusTotal",
      "raw_score": 85.0,
      "weight": 0.4,
      "weighted_score": 34.0,
      "points": ["High detection ratio ≥50% (+50 pts)", ...]
    }
  ]
}
```

### Markdown Report

Human-readable report with:
- Executive summary with severity counts
- Detailed findings sorted by severity
- Score breakdown with point attribution
- MITRE ATT&CK technique mapping
- Kill chain phase references
- Enrichment details (VT detections, AbuseIPDB confidence, Shodan ports/CVEs)
- Geolocation and ASN data
- Methodology appendix

### CSV Report

Spreadsheet-friendly format for SIEM import or Excel analysis.

##  Security Considerations

- **API keys in `.env`** — never commit to Git (`.env` is in `.gitignore`)
- **Rate limiting** — token bucket prevents API abuse
- **Exponential backoff** — handles 429 errors gracefully
- **Private IP detection** — skips external APIs for RFC 1918 addresses
- **Input validation** — prevents injection attacks
- **Request timeouts** — prevents hanging connections
- **Cache TTL** — prevents stale data beyond 24 hours

##  Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test
pytest tests/test_utils.py -v
```

## 🛣️ Roadmap

- [x] Concurrent API enrichment
- [x] Rate limiting with token bucket
- [x] Exponential backoff retry
- [x] IOC deduplication
- [x] Response caching (24h TTL)
- [x] Confidence derivation from source agreement
- [x] Score transparency with point attribution
- [x] Progress bars (tqdm)
- [x] Severity-sorted output
- [x] SQLite case management with audit trail
- [ ] MITRE ATT&CK automatic mapping
- [ ] PDF report export
- [ ] Flask dashboard with search
- [ ] Docker containerization
- [ ] CI/CD with GitHub Actions
- [ ] Additional TI sources (AlienVault OTX, GreyNoise)

##  Blog Post: Building a Mini SOAR Platform in Python

> *"In a typical SOC, analysts spend 15-30 minutes per IOC manually pivoting between VirusTotal, AbuseIPDB, and Shodan. This Python-based automation reduces that to under 30 seconds while producing structured, auditable triage reports with full score transparency and SQLite case management..."*

[Read the full blog post](link-to-your-blog)



