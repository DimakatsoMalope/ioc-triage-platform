#!/usr/bin/env python3
"""
IOC Enrichment and Automated Triage Platform v2.0

Major improvements over v1:
- Concurrent API enrichment (ThreadPoolExecutor)
- Rate limiting with token bucket + exponential backoff retry
- IOC deduplication
- Response caching (24h TTL)
- Progress bars (tqdm)
- Sorted output by severity
- SQLite case management
- Risk score transparency with component breakdown
- Confidence derived from source agreement
- Enhanced Markdown reports with MITRE, kill chain, geolocation

This mirrors real enterprise SOAR platform behavior.
"""

import sys
import csv
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from config.config import Config
from src.utils import classify_ioc, is_private_ip, format_timestamp, deduplicate_iocs, SimpleCache
from src.rate_limiter import RateLimitConfig
from src.virustotal import VirusTotalClient
from src.abuseipdb import AbuseIPDBClient
from src.shodan_lookup import ShodanClient
from src.scoring import ScoringEngine, ScoreResult
from src.report_generator import ReportGenerator
from src.case_manager import CaseManager

logger = Config.setup_logging()


def load_iocs(input_file: Path) -> List[Dict[str, str]]:
    """Load and deduplicate IOCs from CSV file."""
    iocs = []

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            if reader.fieldnames:
                has_type_col = "type" in [h.lower().strip() for h in reader.fieldnames]
            else:
                f.seek(0)
                reader = csv.reader(f)
                has_type_col = False

            for row in reader:
                if isinstance(row, dict):
                    ioc = row.get("ioc", "").strip() or row.get(list(row.keys())[0], "").strip()
                    ioc_type = row.get("type", "").strip().lower() if has_type_col else None
                else:
                    ioc = row[0].strip() if row else ""
                    ioc_type = None

                if not ioc or ioc.startswith("#"):
                    continue

                if not ioc_type:
                    ioc_type = classify_ioc(ioc)

                if ioc_type == "unknown":
                    logger.warning(f"Could not classify IOC: {ioc}")
                    continue

                iocs.append({"ioc": ioc, "type": ioc_type})

    except FileNotFoundError:
        logger.error(f"Input file not found: {input_file}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading input file: {e}")
        sys.exit(1)

    # DEDUPLICATION: Remove duplicate IOCs before enrichment
    original_count = len(iocs)
    iocs = deduplicate_iocs(iocs)
    deduped_count = len(iocs)

    if original_count != deduped_count:
        logger.info(f"Deduplicated: {original_count} → {deduped_count} unique IOCs")

    logger.info(f"Loaded {deduped_count} unique IOCs from {input_file}")
    return iocs


def enrich_single_ioc(
    ioc_data: Dict[str, str],
    vt_client: VirusTotalClient,
    abuse_client: AbuseIPDBClient,
    shodan_client: ShodanClient,
    cache: SimpleCache
) -> Tuple[str, Dict[str, Any]]:
    """
    Enrich a single IOC with all applicable sources.
    Uses caching to avoid redundant API calls.

    Returns: (ioc, enrichment_data)
    """
    ioc = ioc_data["ioc"]
    ioc_type = ioc_data["type"]

    # Check cache first
    cache_key = f"enrichment:{ioc}:{ioc_type}"
    cached = cache.get(cache_key)
    if cached:
        logger.debug(f"Cache hit for {ioc}")
        return ioc, cached

    enrichment = {
        "virustotal": {},
        "abuseipdb": {},
        "shodan": {}
    }

    # VirusTotal - all types
    try:
        if ioc_type == "ip":
            enrichment["virustotal"] = vt_client.query_ip(ioc)
        elif ioc_type == "domain":
            enrichment["virustotal"] = vt_client.query_domain(ioc)
        elif ioc_type == "filehash":
            enrichment["virustotal"] = vt_client.query_filehash(ioc)
        elif ioc_type == "url":
            enrichment["virustotal"] = vt_client.query_url(ioc)
    except Exception as e:
        logger.error(f"VirusTotal failed for {ioc}: {e}")
        enrichment["virustotal"] = {"status": "error", "error": str(e)}

    # AbuseIPDB - IP only, skip private
    if ioc_type == "ip":
        if not is_private_ip(ioc):
            try:
                enrichment["abuseipdb"] = abuse_client.query_ip(ioc, verbose=True)
            except Exception as e:
                logger.error(f"AbuseIPDB failed for {ioc}: {e}")
                enrichment["abuseipdb"] = {"status": "error", "error": str(e)}
        else:
            enrichment["abuseipdb"] = {"status": "skipped", "reason": "Private IP"}

    # Shodan - IP only, skip private
    if ioc_type == "ip":
        if not is_private_ip(ioc):
            try:
                enrichment["shodan"] = shodan_client.query_ip(ioc)
            except Exception as e:
                logger.error(f"Shodan failed for {ioc}: {e}")
                enrichment["shodan"] = {"status": "error", "error": str(e)}
        else:
            enrichment["shodan"] = {"status": "skipped", "reason": "Private IP"}

    # Cache the result
    cache.set(cache_key, enrichment)

    return ioc, enrichment


def run_triage(
    input_file: Path,
    output_formats: List[str] = None,
    skip_private_ips: bool = False,
    max_workers: int = 5,
    create_cases: bool = True
) -> List[Path]:
    """
    Main triage workflow with concurrent enrichment.

    Args:
        input_file: Path to IOC CSV file
        output_formats: List of output formats (json, md, csv)
        skip_private_ips: Whether to skip private IP addresses
        max_workers: Number of concurrent API threads
        create_cases: Whether to create cases in SQLite database

    Returns:
        List of generated report paths
    """
    output_formats = output_formats or ["json", "md", "csv"]

    # Validate configuration
    Config.validate()

    # Initialize components
    logger.info("Initializing SOC automation platform...")
    cache = SimpleCache(ttl_seconds=86400)  # 24h cache

    vt_client = VirusTotalClient()
    abuse_client = AbuseIPDBClient()
    shodan_client = ShodanClient()
    scoring_engine = ScoringEngine()
    report_generator = ReportGenerator()
    case_manager = CaseManager() if create_cases else None

    # Load and deduplicate IOCs
    iocs = load_iocs(input_file)

    if skip_private_ips:
        iocs = [ioc for ioc in iocs if not (ioc["type"] == "ip" and is_private_ip(ioc["ioc"]))]
        logger.info(f"Filtered to {len(iocs)} IOCs (private IPs removed)")

    if not iocs:
        logger.warning("No IOCs to process")
        return []

    # CONCURRENT ENRICHMENT using ThreadPoolExecutor
    logger.info(f"Starting concurrent enrichment with {max_workers} workers...")
    enrichments: Dict[str, Dict[str, Any]] = {}

    try:
        from tqdm import tqdm
        has_tqdm = True
    except ImportError:
        has_tqdm = False
        logger.warning("tqdm not installed. Progress bar disabled. pip install tqdm")

    if has_tqdm:
        pbar = tqdm(total=len(iocs), desc="Enriching IOCs", unit="ioc")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all enrichment tasks
        future_to_ioc = {
            executor.submit(
                enrich_single_ioc,
                ioc_data,
                vt_client,
                abuse_client,
                shodan_client,
                cache
            ): ioc_data["ioc"]
            for ioc_data in iocs
        }

        # Collect results as they complete
        for future in as_completed(future_to_ioc):
            ioc = future_to_ioc[future]
            try:
                _, enrichment = future.result()
                enrichments[ioc] = enrichment
            except Exception as e:
                logger.error(f"Enrichment failed for {ioc}: {e}")
                enrichments[ioc] = {
                    "virustotal": {"status": "error"},
                    "abuseipdb": {"status": "error"},
                    "shodan": {"status": "error"}
                }

            if has_tqdm:
                pbar.update(1)

    if has_tqdm:
        pbar.close()

    # SCORING
    logger.info("Calculating threat scores...")
    results: List[ScoreResult] = []

    for ioc_data in iocs:
        ioc = ioc_data["ioc"]
        ioc_type = ioc_data["type"]
        enrichment = enrichments.get(ioc, {})

        score_result = scoring_engine.calculate_score(
            ioc=ioc,
            ioc_type=ioc_type,
            vt_data=enrichment.get("virustotal"),
            abuse_data=enrichment.get("abuseipdb"),
            shodan_data=enrichment.get("shodan")
        )

        results.append(score_result)

        logger.info(
            f"[{score_result.severity}] {ioc} → Score: {score_result.total_score}/100 "
            f"(Confidence: {score_result.confidence})"
        )

    # SORT BY SEVERITY: Critical first, then High, Medium, Low, Informational
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    results.sort(key=lambda r: (severity_order.get(r.severity, 5), -r.total_score))

    # CASE MANAGEMENT: Create cases for actionable findings
    if case_manager:
        logger.info("Creating investigation cases...")
        cases_created = 0
        for result in results:
            if result.severity in ["Critical", "High"]:
                # Check if case already exists for this IOC
                existing = case_manager.get_case_by_ioc(result.ioc)
                if not existing:
                    case = case_manager.create_case(
                        ioc=result.ioc,
                        ioc_type=result.ioc_type,
                        severity=result.severity,
                        recommendation=result.recommendation,
                        evidence=result.raw_data,
                        title=f"Auto-Triage: {result.ioc}",
                        tags=[result.ioc_type, "auto-triage"]
                    )
                    cases_created += 1
                    logger.info(f"  Created case {case.case_id} for {result.ioc}")

        if cases_created > 0:
            logger.info(f"Created {cases_created} investigation cases")

    # GENERATE REPORTS
    generated_reports = []

    if "json" in output_formats:
        generated_reports.append(
            report_generator.generate_json_report(results, input_file.name)
        )

    if "md" in output_formats:
        generated_reports.append(
            report_generator.generate_markdown_report(results, input_file.name)
        )

    if "csv" in output_formats:
        generated_reports.append(
            report_generator.generate_csv_report(results, input_file.name)
        )

    # CONSOLE SUMMARY
    print("\n" + "="*70)
    print("🛡️  TRIAGE COMPLETE")
    print("="*70)

    summary = {
        "Critical": sum(1 for r in results if r.severity == "Critical"),
        "High": sum(1 for r in results if r.severity == "High"),
        "Medium": sum(1 for r in results if r.severity == "Medium"),
        "Low": sum(1 for r in results if r.severity == "Low"),
        "Informational": sum(1 for r in results if r.severity == "Informational")
    }

    severity_emoji = {
        "Critical": "🔴", "High": "🟠", "Medium": "🟡",
        "Low": "🟢", "Informational": "⚪"
    }

    for sev, count in summary.items():
        if count > 0:
            print(f"  {severity_emoji[sev]} {sev}: {count}")

    require_action = summary["Critical"] + summary["High"]
    print(f"\n  ⚠️  Require Immediate Action: {require_action}")

    if case_manager:
        stats = case_manager.get_stats()
        print(f"  📁 Cases Created: {stats['open_cases']} open")

    print(f"\n  📄 Reports Generated:")
    for report in generated_reports:
        print(f"     • {report.name}")

    print(f"\n  💾 Cache Stats: {cache.stats()['entries']} entries")
    print("="*70)

    return generated_reports


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="IOC Enrichment and Automated Triage Platform v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src/main.py -i input/iocs.csv
  python src/main.py -i input/iocs.csv --formats json csv --workers 3
  python src/main.py -i input/iocs.csv --skip-private --no-cases
  python src/main.py --validate
        """
    )

    parser.add_argument(
        "-i", "--input",
        type=Path,
        default=Config.INPUT_DIR / "iocs.csv",
        help="Input CSV file with IOCs (default: input/iocs.csv)"
    )

    parser.add_argument(
        "--formats",
        nargs="+",
        choices=["json", "md", "csv"],
        default=["json", "md", "csv"],
        help="Output report formats"
    )

    parser.add_argument(
        "--skip-private",
        action="store_true",
        help="Skip private IP addresses"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=5,
        help="Concurrent API workers (default: 5)"
    )

    parser.add_argument(
        "--no-cases",
        action="store_true",
        help="Disable case management (no SQLite DB)"
    )

    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate configuration and exit"
    )

    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear API response cache"
    )

    args = parser.parse_args()

    if args.validate:
        try:
            Config.validate()
            print("✅ Configuration valid")
            sys.exit(0)
        except ValueError as e:
            print(f"❌ Configuration error: {e}")
            sys.exit(1)

    if args.clear_cache:
        cache = SimpleCache()
        cache.clear()
        print("🗑️  Cache cleared")
        sys.exit(0)

    if not args.input.exists():
        print(f"❌ Input file not found: {args.input}")
        sys.exit(1)

    run_triage(
        args.input,
        args.formats,
        args.skip_private,
        args.workers,
        create_cases=not args.no_cases
    )


if __name__ == "__main__":
    main()
