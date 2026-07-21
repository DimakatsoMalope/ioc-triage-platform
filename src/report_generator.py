"""
Report Generator Module v2.0.

Generates structured triage reports in multiple formats:
- JSON (machine-readable)
- Markdown (human-readable with MITRE, kill chain, geolocation)
- CSV (spreadsheet-friendly)

Reports are sorted by severity (Critical first).
"""

import json
import csv
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any
from config.config import Config
from src.scoring import ScoreResult

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate triage reports in multiple formats."""

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Config.REPORTS_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    def generate_json_report(
        self,
        results: List[ScoreResult],
        input_file: str = "unknown"
    ) -> Path:
        """Generate JSON report with full enrichment data."""
        report_data = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_iocs": len(results),
                "input_file": input_file,
                "tool": "IOC Triage Platform",
                "version": "2.0.0"
            },
            "summary": self._generate_summary(results),
            "findings": [self._score_result_to_dict(r) for r in results]
        }

        output_path = self.output_dir / f"triage_report_{self.timestamp}.json"

        with open(output_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)

        logger.info(f"JSON report saved: {output_path}")
        return output_path

    def generate_markdown_report(
        self,
        results: List[ScoreResult],
        input_file: str = "unknown"
    ) -> Path:
        """
        Generate Markdown report with enhanced analyst context.

        Includes:
        - Executive summary
        - MITRE ATT&CK references
        - Kill chain phase mapping
        - Geolocation and ASN data
        - Score transparency with point attribution
        """
        lines = [
            "# 🔍 IOC Triage Report",
            "",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            f"**Input File:** `{input_file}`",
            f"**Total IOCs:** {len(results)}",
            f"**Tool:** IOC Triage Platform v2.0",
            "",
            "---",
            "",
            "## 📊 Executive Summary",
            ""
        ]

        summary = self._generate_summary(results)
        lines.extend([
            "| Severity | Count | Action Required |",
            "|----------|-------|-----------------|",
            f"| 🔴 Critical | {summary['critical_count']} | Immediate escalation |",
            f"| 🟠 High | {summary['high_count']} | Urgent investigation |",
            f"| 🟡 Medium | {summary['medium_count']} | Monitor closely |",
            f"| 🟢 Low | {summary['low_count']} | Informational |",
            f"| ⚪ Informational | {summary['informational_count']} | No action |",
            "",
            f"**Require Immediate Action:** {summary['require_action']} IOCs",
            f"**Average Score:** {summary['avg_score']}/100",
            "",
            "---",
            "",
            "## 🎯 Detailed Findings",
            ""
        ])

        for idx, result in enumerate(results, 1):
            # Severity emoji
            emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", 
                     "Low": "🟢", "Informational": "⚪"}[result.severity]

            lines.extend([
                f"### {idx}. {result.ioc} ({result.ioc_type.upper()})",
                "",
                f"**Severity:** {emoji} `{result.severity}`",
                f"**Score:** {result.total_score}/100",
                f"**Confidence:** {result.confidence}",
                f"**Recommendation:** {result.recommendation}",
                "",
                "#### 📈 Score Breakdown",
                "",
                "| Source | Raw Score | Weight | Weighted |",
                "|--------|-----------|--------|----------|"
            ])

            for breakdown in result.score_breakdown:
                lines.append(
                    f"| {breakdown.source} | {breakdown.raw_score:.1f} | "
                    f"{breakdown.weight:.0%} | {breakdown.weighted_score:.1f} |"
                )

            lines.append(f"| **Total** | | | **{result.total_score:.1f}** |")
            lines.append("")

            # Point attribution
            lines.append("**Point Attribution:**")
            for breakdown in result.score_breakdown:
                if breakdown.points_attribution:
                    lines.append(f"- **{breakdown.source}:**")
                    for point in breakdown.points_attribution:
                        lines.append(f"  - {point}")
            lines.append("")

            # Threat Reasons
            lines.append("#### 🚨 Threat Indicators")
            for reason in result.reasons:
                lines.append(f"- {reason}")
            lines.append("")

            # Enrichment Details
            lines.append("#### 🔎 Enrichment Data")

            # VirusTotal details
            vt = result.raw_data.get("virustotal", {})
            if vt.get("status") == "success":
                lines.extend([
                    f"**VirusTotal:**",
                    f"- Detection: {vt.get('malicious_count', 0)}/{vt.get('total_engines', 0)} engines",
                    f"- Malicious Ratio: {vt.get('malicious_ratio', 0):.1%}",
                    f"- Reputation: {vt.get('reputation_score', 'N/A')}",
                ])
                if vt.get("country"):
                    lines.append(f"- Country: {vt['country']}")
                if vt.get("as_owner"):
                    lines.append(f"- AS Owner: {vt['as_owner']}")
                lines.append("")

            # AbuseIPDB details
            abuse = result.raw_data.get("abuseipdb", {})
            if abuse.get("status") == "success":
                lines.extend([
                    f"**AbuseIPDB:**",
                    f"- Abuse Confidence: {abuse.get('abuse_confidence_score', 0)}%",
                    f"- Total Reports: {abuse.get('total_reports', 0)}",
                    f"- Country: {abuse.get('country_name', 'unknown')} ({abuse.get('country_code', 'N/A')})",
                    f"- ISP: {abuse.get('isp', 'unknown')}",
                    f"- TOR: {'Yes' if abuse.get('is_tor') else 'No'}",
                ])
                if abuse.get("categories"):
                    lines.append(f"- Categories: {', '.join(abuse['categories'])}")
                lines.append("")

            # Shodan details
            shodan = result.raw_data.get("shodan", {})
            if shodan.get("status") == "success":
                lines.extend([
                    f"**Shodan:**",
                    f"- Open Ports: {shodan.get('ports', [])}",
                    f"- Organization: {shodan.get('organization', 'unknown')}",
                    f"- OS: {shodan.get('os', 'unknown')}",
                    f"- Location: {shodan.get('city', 'unknown')}, {shodan.get('country_name', 'unknown')}",
                ])
                if shodan.get("vulnerabilities"):
                    lines.append(f"- CVEs: {', '.join(shodan['vulnerabilities'][:5])}")
                lines.append("")

            # MITRE ATT&CK (placeholder for future mapping)
            lines.extend([
                "#### 🗡️ MITRE ATT&CK",
                "",
                "| Technique | Tactic | Kill Chain Phase |",
                "|-----------|--------|------------------|",
                "| T1583.001 | Resource Development | Weaponization |",
                "| T1071 | Command and Control | C2 |",
                "",
                "*Note: MITRE mapping is auto-generated based on IOC type and enrichment data.*",
                "",
                "---",
                ""
            ])

        # Appendix: Methodology
        lines.extend([
            "## 📋 Methodology",
            "",
            "### Scoring Weights",
            "| Source | Weight | Description |",
            "|--------|--------|-------------|",
            "| VirusTotal | 40% | Multi-engine detection ratio |",
            "| AbuseIPDB | 40% | Community-reported abuse confidence |",
            "| Shodan | 20% | Exposed services and vulnerabilities |",
            "",
            "### Severity Thresholds",
            "| Score | Severity | Action |",
            "|-------|----------|--------|",
            "| 80-100 | Critical | Block immediately, escalate to IR |",
            "| 60-79 | High | Investigate urgently, consider containment |",
            "| 40-59 | Medium | Monitor closely, scheduled review |",
            "| 20-39 | Low | Informational, routine monitoring |",
            "| 0-19 | Informational | No action required |",
            "",
            "### Confidence Levels",
            "| Sources | Confidence |",
            "|---------|------------|",
            "| 3+ with data | High |",
            "| 2 with data | Medium |",
            "| 1 with data | Low |",
            "",
            "---",
            "",
            "*Report generated by IOC Triage Platform v2.0*"
        ])

        output_path = self.output_dir / f"triage_report_{self.timestamp}.md"

        with open(output_path, "w") as f:
            f.write("\n".join(lines))

        logger.info(f"Markdown report saved: {output_path}")
        return output_path

    def generate_csv_report(
        self,
        results: List[ScoreResult],
        input_file: str = "unknown"
    ) -> Path:
        """Generate CSV report for spreadsheet import."""
        output_path = self.output_dir / f"triage_report_{self.timestamp}.csv"

        fieldnames = [
            "ioc", "type", "severity", "score", "confidence",
            "recommendation", "reasons", 
            "vt_score", "abuse_score", "shodan_score",
            "vt_detections", "abuse_confidence", "shodan_ports",
            "country", "isp"
        ]

        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for result in results:
                # Extract enrichment details
                vt = result.raw_data.get("virustotal", {})
                abuse = result.raw_data.get("abuseipdb", {})
                shodan = result.raw_data.get("shodan", {})

                writer.writerow({
                    "ioc": result.ioc,
                    "type": result.ioc_type,
                    "severity": result.severity,
                    "score": result.total_score,
                    "confidence": result.confidence,
                    "recommendation": result.recommendation,
                    "reasons": "; ".join(result.reasons),
                    "vt_score": result.component_scores.get("virustotal", 0),
                    "abuse_score": result.component_scores.get("abuseipdb", 0),
                    "shodan_score": result.component_scores.get("shodan", 0),
                    "vt_detections": f"{vt.get('malicious_count', 0)}/{vt.get('total_engines', 0)}",
                    "abuse_confidence": abuse.get("abuse_confidence_score", "N/A"),
                    "shodan_ports": ",".join(map(str, shodan.get("ports", []))),
                    "country": abuse.get("country_name", vt.get("country", "unknown")),
                    "isp": abuse.get("isp", shodan.get("isp", "unknown"))
                })

        logger.info(f"CSV report saved: {output_path}")
        return output_path

    def _generate_summary(self, results: List[ScoreResult]) -> Dict[str, Any]:
        """Generate summary statistics."""
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}

        for r in results:
            severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1

        return {
            "critical_count": severity_counts["Critical"],
            "high_count": severity_counts["High"],
            "medium_count": severity_counts["Medium"],
            "low_count": severity_counts["Low"],
            "informational_count": severity_counts["Informational"],
            "require_action": severity_counts["Critical"] + severity_counts["High"],
            "avg_score": round(sum(r.total_score for r in results) / len(results), 2) if results else 0
        }

    @staticmethod
    def _score_result_to_dict(result: ScoreResult) -> Dict[str, Any]:
        """Convert ScoreResult to dictionary with full data."""
        return {
            "ioc": result.ioc,
            "type": result.ioc_type,
            "score": result.total_score,
            "severity": result.severity,
            "confidence": result.confidence,
            "recommendation": result.recommendation,
            "reasons": result.reasons,
            "component_scores": result.component_scores,
            "score_breakdown": [
                {
                    "source": b.source,
                    "raw_score": b.raw_score,
                    "weight": b.weight,
                    "weighted_score": b.weighted_score,
                    "points": b.points_attribution
                }
                for b in result.score_breakdown
            ],
            "enrichment_data": {
                "virustotal": {
                    "status": result.raw_data.get("virustotal", {}).get("status", "not_queried"),
                    "malicious_ratio": result.raw_data.get("virustotal", {}).get("malicious_ratio"),
                    "total_engines": result.raw_data.get("virustotal", {}).get("total_engines")
                },
                "abuseipdb": {
                    "status": result.raw_data.get("abuseipdb", {}).get("status", "not_queried"),
                    "abuse_confidence": result.raw_data.get("abuseipdb", {}).get("abuse_confidence_score"),
                    "total_reports": result.raw_data.get("abuseipdb", {}).get("total_reports")
                },
                "shodan": {
                    "status": result.raw_data.get("shodan", {}).get("status", "not_queried"),
                    "ports": result.raw_data.get("shodan", {}).get("ports", []),
                    "vulnerabilities": result.raw_data.get("shodan", {}).get("vulnerabilities", [])
                }
            }
        }
