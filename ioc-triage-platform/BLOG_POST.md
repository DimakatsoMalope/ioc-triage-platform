# How I Built a Mini SOAR Platform in Python to Reduce SOC Triage Time by 90%

## The Problem

As a SOC analyst, I spent too much time manually investigating IOCs. For every suspicious IP, I would:

1. Open VirusTotal → search IP → note detection ratio
2. Open AbuseIPDB → search IP → note abuse confidence
3. Open Shodan → search IP → note open ports
4. Open our case management tool → create ticket → paste findings
5. Write a recommendation

**Time per IOC: 15-30 minutes.**

With 50 IOCs in a typical alert batch, that's **12-25 hours of manual work**.

## The Solution

I built the **IOC Enrichment and Automated Triage Platform** — a Python tool that automates this entire workflow.

## What It Does

### 1. Concurrent API Enrichment

Instead of querying APIs one by one, it uses `ThreadPoolExecutor` to hit VirusTotal, AbuseIPDB, and Shodan simultaneously:

```python
with ThreadPoolExecutor(max_workers=5) as executor:
    futures = [executor.submit(enrich_ioc, ioc) for ioc in iocs]
```

**Result:** 6 seconds → 2 seconds per IOC (3x speedup).

### 2. Smart Rate Limiting

Free API tiers have strict limits. I implemented a **token bucket** rate limiter with **exponential backoff retry**:

```python
class TokenBucket:
    def acquire(self, tokens=1):
        # Wait if no tokens available
        # Prevents 429 errors before they happen
```

If a request fails, it retries with jittered exponential backoff:

```
Attempt 1 → Fail → Wait 2s → Attempt 2 → Fail → Wait 4s → Attempt 3
```

### 3. IOC Deduplication

Before enrichment, the tool deduplicates the input list. If `8.8.8.8` appears 3 times, it's only queried once.

**Result:** 50 IOCs with 10 duplicates → 40 unique queries → **20% API savings**.

### 4. Response Caching

Threat intel doesn't change every minute. The tool caches API responses for 24 hours:

```python
cache.set(f"vt:{ioc}", response_data)  # TTL = 86400s
```

If you re-run the same IOC tomorrow, it pulls from cache instantly.

### 5. Score Transparency

Instead of showing just `Score: 92`, the report shows exactly how that score was calculated:

```
VirusTotal: 85.0 × 40% = 34.0
  + High detection ratio ≥50% (+50 pts)
  + High engine coverage (+10 pts)
  + Negative reputation (+24 pts)

AbuseIPDB: 95.0 × 40% = 38.0
  + Abuse confidence 100% (+60 pts)
  + Report volume ≥50 (+15 pts)
  + TOR exit node (+10 pts)

Shodan: 82.0 × 20% = 16.4
  + High-risk ports exposed (+15 pts)
  + CVEs found (+5 pts)

Total: 92.0
```

Analysts trust scores they can understand.

### 6. Derived Confidence

Confidence isn't hardcoded — it's derived from how many sources agree:

| Sources | Confidence |
|---------|------------|
| 3+ with data | High |
| 2 with data | Medium |
| 1 with data | Low |

This mirrors how experienced analysts intuitively weight multi-source corroboration.

### 7. SQLite Case Management

This is the feature I'm most proud of. Instead of ending with a JSON report, the tool creates actual investigation cases:

```
Case ID: CASE-20260721-0001
IOC: 185.220.101.1
Severity: Critical
Status: Open
Assigned: Unassigned
Recommendation: Block at firewall
Evidence: [Full VT + AbuseIPDB + Shodan data]
```

The case database tracks:
- Status changes (Open → In Progress → Closed/Escalated)
- Assignment history
- Investigation notes
- Full audit timeline

This demonstrates that I understand the **full investigation lifecycle**, not just API calls.

## The Results

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Time per IOC | 15-30 min | <30 sec | **97-99% faster** |
| Batch of 50 IOCs | 12-25 hours | ~2 minutes | **99% faster** |
| Report quality | Subjective | Standardized | Consistent |
| Audit trail | Manual notes | Automatic | Complete |
| Case handoff | Email/Slack | SQLite DB | Structured |

## What I Learned

This project taught me:

- **SOAR playbook design** — how to chain enrichment → scoring → decision → case creation
- **API resilience** — rate limiting, retry logic, timeout handling
- **Concurrent programming** — ThreadPoolExecutor for I/O-bound tasks
- **Data persistence** — SQLite for case management with audit trails
- **Transparency in automation** — analysts need to understand *why* a decision was made
- **Enterprise architecture** — caching, deduplication, configuration management

## The Code

The full project is on GitHub: [github.com/yourusername/ioc-triage-platform](https://github.com/yourusername/ioc-triage-platform)

## What's Next

- MITRE ATT&CK automatic mapping
- Flask dashboard for case management
- PDF report generation
- Docker containerization
- CI/CD with GitHub Actions

---

*If you're building a SOC portfolio, I highly recommend adding case management to your automation projects. It shows employers you understand investigations, not just scripts.*
