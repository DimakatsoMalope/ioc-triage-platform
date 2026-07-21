"""
AbuseIPDB API integration module.

Uses AbuseIPDB API v2 for IP reputation checking.
API docs: https://docs.abuseipdb.com/
"""

import requests
import time
import logging
from typing import Dict, Optional, Any, List
from config.config import Config

logger = logging.getLogger(__name__)


class AbuseIPDBClient:
    """Client for AbuseIPDB API v2."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or Config.ABUSEIPDB_API_KEY
        self.base_url = Config.ABUSEIPDB_BASE_URL
        self.headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.last_request_time = 0
        self.min_request_interval = 1.5  # ~40 requests/minute for free tier

    def _rate_limit(self):
        """Enforce rate limiting between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            sleep_time = self.min_request_interval - elapsed
            logger.debug(f"Rate limiting: sleeping {sleep_time:.1f}s")
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make a rate-limited API request."""
        self._rate_limit()

        try:
            response = self.session.get(endpoint, params=params, timeout=30)

            if response.status_code == 429:
                # Check Retry-After header
                retry_after = int(response.headers.get("Retry-After", 60))
                logger.warning(f"AbuseIPDB rate limit exceeded. Waiting {retry_after}s...")
                time.sleep(retry_after)
                return self._make_request(endpoint, params)

            response.raise_for_status()
            return response.json()

        except requests.exceptions.Timeout:
            logger.error(f"Timeout querying AbuseIPDB: {endpoint}")
            return {"error": "Request timeout", "status": "failed"}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for AbuseIPDB: {e}")
            return {"error": str(e), "status": "failed"}

    def query_ip(self, ip: str, max_age_in_days: int = 90, verbose: bool = False) -> Dict[str, Any]:
        """
        Query AbuseIPDB for IP reputation.

        Args:
            ip: IP address to query
            max_age_in_days: Maximum age of reports to include (1-365)
            verbose: Include individual reports in response

        Returns:
            Enriched data with abuse confidence score and report details
        """
        endpoint = f"{self.base_url}/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": max(min(max_age_in_days, 365), 1),
            "verbose": verbose
        }

        data = self._make_request(endpoint, params)

        if "errors" in data or "error" in data:
            error_msg = data.get("errors", [{}])[0].get("detail", data.get("error", "Unknown error"))
            return {
                "source": "abuseipdb",
                "ioc": ip,
                "type": "ip",
                "status": "error",
                "error": error_msg
            }

        ip_data = data.get("data", {})

        # Extract report categories if verbose
        categories: List[str] = []
        if verbose and "reports" in ip_data:
            category_map = {
                1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
                4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
                7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
                11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
                15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
                19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
                22: "SSH", 23: "IoT Targeted"
            }
            seen_cats = set()
            for report in ip_data["reports"]:
                for cat_id in report.get("categories", []):
                    if cat_id in category_map:
                        seen_cats.add(category_map[cat_id])
            categories = list(seen_cats)

        return {
            "source": "abuseipdb",
            "ioc": ip,
            "type": "ip",
            "status": "success",
            "abuse_confidence_score": ip_data.get("abuseConfidenceScore", 0),
            "country_code": ip_data.get("countryCode", "unknown"),
            "country_name": ip_data.get("countryName", "unknown"),
            "usage_type": ip_data.get("usageType", "unknown"),
            "isp": ip_data.get("isp", "unknown"),
            "domain": ip_data.get("domain", "unknown"),
            "is_tor": ip_data.get("isTor", False),
            "is_whitelisted": ip_data.get("isWhitelisted", False),
            "total_reports": ip_data.get("totalReports", 0),
            "num_distinct_users": ip_data.get("numDistinctUsers", 0),
            "last_reported_at": ip_data.get("lastReportedAt", "unknown"),
            "categories": categories,
            "raw_data": data
        }

    def check_blacklist(self, confidence_minimum: int = 90, limit: int = 100) -> Dict[str, Any]:
        """
        Retrieve AbuseIPDB blacklist.

        Args:
            confidence_minimum: Minimum abuse confidence (25-100)
            limit: Maximum number of IPs to return

        Returns:
            List of blacklisted IPs
        """
        endpoint = f"{self.base_url}/blacklist"
        params = {
            "confidenceMinimum": max(min(confidence_minimum, 100), 25),
            "limit": min(limit, 10000)
        }

        data = self._make_request(endpoint, params)

        if "errors" in data or "error" in data:
            return {
                "source": "abuseipdb",
                "type": "blacklist",
                "status": "error",
                "error": data.get("errors", [{}])[0].get("detail", "Unknown error")
            }

        return {
            "source": "abuseipdb",
            "type": "blacklist",
            "status": "success",
            "generated_at": data.get("meta", {}).get("generatedAt", "unknown"),
            "blacklist": data.get("data", []),
            "count": len(data.get("data", []))
        }
