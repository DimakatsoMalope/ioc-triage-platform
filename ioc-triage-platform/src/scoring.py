"""
IOC Scoring Engine v2.0.

Implements a weighted scoring algorithm with:
- Component score transparency (analysts see the breakdown)
- Confidence derived from source agreement
- Risk score explanation with point attribution
"""

import logging
from typing import Dict, Any, List, Literal
from dataclasses import dataclass, field
from config.config import Config

logger = logging.getLogger(__name__)


@dataclass
class ScoreBreakdown:
    """Transparent score breakdown for analyst trust."""
    source: str
    raw_score: float
    weight: float
    weighted_score: float
    max_possible: float
    points_attribution: List[str]


@dataclass
class ScoreResult:
    """Result of scoring an IOC with full transparency."""
    ioc: str
    ioc_type: str
    total_score: float
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"]
    confidence: Literal["High", "Medium", "Low"]
    reasons: List[str] = field(default_factory=list)
    recommendation: str = ""
    component_scores: Dict[str, float] = field(default_factory=dict)
    score_breakdown: List[ScoreBreakdown] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def get_explanation(self) -> str:
        """Generate human-readable score explanation."""
        lines = [
            f"Score: {self.total_score}/100",
            f"Severity: {self.severity}",
            f"Confidence: {self.confidence}",
            "",
            "Score Breakdown:"
        ]

        for breakdown in self.score_breakdown:
            lines.append(
                f"  {breakdown.source}: {breakdown.raw_score:.1f} × {breakdown.weight:.0%} = "
                f"{breakdown.weighted_score:.1f}"
            )
            for point in breakdown.points_attribution:
                lines.append(f"    + {point}")

        lines.append(f"\nTotal: {self.total_score:.1f}")
        return "\n".join(lines)


class ScoringEngine:
    """
    Multi-source threat scoring engine with full transparency.
    """

    CRITICAL_THRESHOLD = 80
    HIGH_THRESHOLD = 60
    MEDIUM_THRESHOLD = 40
    LOW_THRESHOLD = 20

    def __init__(self):
        self.vt_weight = Config.VT_WEIGHT
        self.abuse_weight = Config.ABUSEIPDB_WEIGHT
        self.shodan_weight = Config.SHODAN_WEIGHT

    def _score_virustotal(self, vt_data: Dict[str, Any]) -> tuple[float, List[str], List[str]]:
        """
        Score VirusTotal data.
        Returns: (score_0_100, reasons, point_attributions)
        """
        if vt_data.get("status") == "error":
            return 0, ["VirusTotal lookup failed"], ["Lookup failed (0 pts)"]

        score = 0.0
        reasons = []
        points = []

        malicious_ratio = vt_data.get("malicious_ratio", 0)
        total_engines = vt_data.get("total_engines", 0)

        # Detection ratio scoring
        if malicious_ratio >= 0.5:
            score += 50
            reasons.append(f"High VT detection: {malicious_ratio:.1%} ({vt_data.get('malicious_count', 0)}/{total_engines})")
            points.append(f"High detection ratio ≥50% (+50 pts)")
        elif malicious_ratio >= 0.2:
            score += 30
            reasons.append(f"Moderate VT detection: {malicious_ratio:.1%}")
            points.append(f"Moderate detection ratio ≥20% (+30 pts)")
        elif malicious_ratio > 0:
            score += 10
            reasons.append(f"Low VT detection: {malicious_ratio:.1%}")
            points.append(f"Low detection ratio >0% (+10 pts)")
        else:
            points.append("No detections (0 pts)")

        # Engine count confidence bonus
        if total_engines >= 60:
            score += 10
            points.append(f"High engine coverage ≥60 (+10 pts)")

        # Reputation
        reputation = vt_data.get("reputation_score", 0)
        if reputation < 0:
            rep_penalty = min(abs(reputation) * 2, 20)
            score += rep_penalty
            reasons.append(f"Negative VT reputation: {reputation}")
            points.append(f"Negative reputation {reputation} (+{rep_penalty:.0f} pts)")

        # File type bonus
        if vt_data.get("type") == "filehash":
            if vt_data.get("file_type") in ["Win32 EXE", "ELF", "Mach-O"]:
                score += 10
                reasons.append("Executable file type detected")
                points.append("Executable file type (+10 pts)")

        return min(score, 100), reasons, points

    def _score_abuseipdb(self, abuse_data: Dict[str, Any]) -> tuple[float, List[str], List[str]]:
        """Score AbuseIPDB data."""
        if abuse_data.get("status") == "error":
            return 0, ["AbuseIPDB lookup failed"], ["Lookup failed (0 pts)"]
        if abuse_data.get("status") == "skipped":
            return 0, [f"AbuseIPDB skipped: {abuse_data.get('reason', '')}"], ["Skipped (0 pts)"]

        score = 0.0
        reasons = []
        points = []

        abuse_score = abuse_data.get("abuse_confidence_score", 0)
        total_reports = abuse_data.get("total_reports", 0)

        # Abuse confidence score
        if abuse_score >= 80:
            pts = abuse_score * 0.6
            score += pts
            reasons.append(f"Very high abuse confidence: {abuse_score}%")
            points.append(f"Abuse confidence {abuse_score}% (+{pts:.0f} pts)")
        elif abuse_score >= 50:
            pts = abuse_score * 0.5
            score += pts
            reasons.append(f"High abuse confidence: {abuse_score}%")
            points.append(f"Abuse confidence {abuse_score}% (+{pts:.0f} pts)")
        elif abuse_score >= 25:
            pts = abuse_score * 0.3
            score += pts
            reasons.append(f"Moderate abuse confidence: {abuse_score}%")
            points.append(f"Abuse confidence {abuse_score}% (+{pts:.0f} pts)")
        elif abuse_score > 0:
            pts = abuse_score * 0.1
            score += pts
            reasons.append(f"Low abuse confidence: {abuse_score}%")
            points.append(f"Abuse confidence {abuse_score}% (+{pts:.0f} pts)")
        else:
            points.append("No abuse reports (0 pts)")

        # Report volume
        if total_reports >= 50:
            score += 15
            reasons.append(f"High report volume: {total_reports} reports")
            points.append(f"Report volume ≥50 (+15 pts)")
        elif total_reports >= 10:
            score += 8
            reasons.append(f"Moderate report volume: {total_reports} reports")
            points.append(f"Report volume ≥10 (+8 pts)")
        elif total_reports > 0:
            score += 3
            points.append(f"Some reports ({total_reports}) (+3 pts)")

        # TOR
        if abuse_data.get("is_tor"):
            score += 10
            reasons.append("TOR exit node detected")
            points.append("TOR exit node (+10 pts)")

        # Categories
        categories = abuse_data.get("categories", [])
        high_risk_cats = {"Brute-Force", "Hacking", "Web App Attack", "Exploited Host", "Phishing"}
        matched = set(categories) & high_risk_cats
        if matched:
            score += 10
            reasons.append(f"High-risk activity: {list(matched)}")
            points.append(f"High-risk categories: {list(matched)} (+10 pts)")

        return min(score, 100), reasons, points

    def _score_shodan(self, shodan_data: Dict[str, Any]) -> tuple[float, List[str], List[str]]:
        """Score Shodan data."""
        if shodan_data.get("status") == "error":
            return 0, ["Shodan lookup failed"], ["Lookup failed (0 pts)"]
        if shodan_data.get("status") == "skipped":
            return 0, [f"Shodan skipped: {shodan_data.get('reason', '')}"], ["Skipped (0 pts)"]

        score = 0.0
        reasons = []
        points = []

        risk_indicators = shodan_data.get("risk_indicators", [])
        ports = shodan_data.get("ports", [])
        vulns = shodan_data.get("vulnerabilities", [])

        # Risk indicators
        for indicator in risk_indicators:
            if "High-risk ports" in indicator:
                score += 15
                reasons.append(indicator)
                points.append(f"High-risk ports exposed (+15 pts)")
            elif "Medium-risk ports" in indicator:
                score += 8
                reasons.append(indicator)
                points.append(f"Medium-risk ports exposed (+8 pts)")
            elif "vulnerabilities" in indicator.lower():
                score += 20
                reasons.append(indicator)
                points.append(f"Known CVEs found (+20 pts)")
            elif "Tags" in indicator:
                score += 5
                reasons.append(indicator)
                points.append(f"Risk tags present (+5 pts)")

        # Vulnerability count
        if len(vulns) >= 5:
            score += 15
            reasons.append(f"Multiple CVEs found: {len(vulns)}")
            points.append(f"CVEs ≥5 (+15 pts)")
        elif len(vulns) > 0:
            score += 5
            reasons.append(f"CVEs found: {len(vulns)}")
            points.append(f"CVEs found ({len(vulns)}) (+5 pts)")
        else:
            points.append("No known CVEs (0 pts)")

        # Exposed services
        high_risk_ports = {22, 23, 3389, 445, 135, 3306, 5432, 6379, 27017, 9200}
        exposed_high_risk = set(ports) & high_risk_ports
        if exposed_high_risk:
            pts = len(exposed_high_risk) * 3
            score += pts
            points.append(f"Exposed high-risk ports: {sorted(exposed_high_risk)} (+{pts} pts)")

        return min(score, 100), reasons, points

    def calculate_score(
        self,
        ioc: str,
        ioc_type: str,
        vt_data: Dict[str, Any] = None,
        abuse_data: Dict[str, Any] = None,
        shodan_data: Dict[str, Any] = None
    ) -> ScoreResult:
        """
        Calculate composite threat score with full transparency.

        Confidence is DERIVED from source agreement:
        - 3+ sources with data → High confidence
        - 2 sources with data → Medium confidence
        - 1 source with data → Low confidence
        - 0 sources → Lowest confidence
        """
        vt_data = vt_data or {}
        abuse_data = abuse_data or {}
        shodan_data = shodan_data or {}

        # Calculate component scores with point attribution
        vt_score, vt_reasons, vt_points = self._score_virustotal(vt_data)
        abuse_score, abuse_reasons, abuse_points = self._score_abuseipdb(abuse_data)
        shodan_score, shodan_reasons, shodan_points = self._score_shodan(shodan_data)

        # Weighted composite score
        total_score = (
            vt_score * self.vt_weight +
            abuse_score * self.abuse_weight +
            shodan_score * self.shodan_weight
        )

        # Build score breakdown for transparency
        breakdown = [
            ScoreBreakdown(
                source="VirusTotal",
                raw_score=vt_score,
                weight=self.vt_weight,
                weighted_score=vt_score * self.vt_weight,
                max_possible=100 * self.vt_weight,
                points_attribution=vt_points
            ),
            ScoreBreakdown(
                source="AbuseIPDB",
                raw_score=abuse_score,
                weight=self.abuse_weight,
                weighted_score=abuse_score * self.abuse_weight,
                max_possible=100 * self.abuse_weight,
                points_attribution=abuse_points
            ),
            ScoreBreakdown(
                source="Shodan",
                raw_score=shodan_score,
                weight=self.shodan_weight,
                weighted_score=shodan_score * self.shodan_weight,
                max_possible=100 * self.shodan_weight,
                points_attribution=shodan_points
            )
        ]

        # Combine all reasons
        all_reasons = vt_reasons + abuse_reasons + shodan_reasons

        # Determine severity
        if total_score >= self.CRITICAL_THRESHOLD:
            severity = "Critical"
            recommendation = "BLOCK IMMEDIATELY - Escalate to incident response"
        elif total_score >= self.HIGH_THRESHOLD:
            severity = "High"
            recommendation = "INVESTIGATE URGENTLY - Deep dive required, consider containment"
        elif total_score >= self.MEDIUM_THRESHOLD:
            severity = "Medium"
            recommendation = "MONITOR CLOSELY - Track activity, scheduled review"
        elif total_score >= self.LOW_THRESHOLD:
            severity = "Low"
            recommendation = "INFORMATIONAL - Log for correlation, routine monitoring"
        else:
            severity = "Informational"
            recommendation = "NO ACTION - Benign or insufficient data"

        # DERIVE confidence from source agreement (not hardcoded)
        sources_with_data = 0
        if vt_data.get("status") == "success":
            sources_with_data += 1
        if abuse_data.get("status") == "success":
            sources_with_data += 1
        if shodan_data.get("status") == "success":
            sources_with_data += 1

        # Also consider total engines for VT confidence
        vt_engines = vt_data.get("total_engines", 0)

        if sources_with_data >= 3 and vt_engines >= 50:
            confidence = "High"
        elif sources_with_data >= 2:
            confidence = "Medium"
        elif sources_with_data >= 1:
            confidence = "Low"
        else:
            confidence = "Low"  # Fallback

        if not all_reasons:
            all_reasons.append("No significant threat indicators found")

        return ScoreResult(
            ioc=ioc,
            ioc_type=ioc_type,
            total_score=round(total_score, 2),
            severity=severity,
            confidence=confidence,
            reasons=all_reasons,
            recommendation=recommendation,
            component_scores={
                "virustotal": round(vt_score, 2),
                "abuseipdb": round(abuse_score, 2),
                "shodan": round(shodan_score, 2)
            },
            score_breakdown=breakdown,
            raw_data={
                "virustotal": vt_data,
                "abuseipdb": abuse_data,
                "shodan": shodan_data
            }
        )

    @staticmethod
    def get_severity_color(severity: str) -> str:
        """Get color code for severity level."""
        colors = {
            "Critical": "\033[91m",
            "High": "\033[93m",
            "Medium": "\033[94m",
            "Low": "\033[92m",
            "Informational": "\033[90m"
        }
        return colors.get(severity, "\033[0m")
