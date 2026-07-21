"""
VirusTotal API integration module.

Uses VirusTotal API v3 for IOC enrichment.
API docs: https://developers.virustotal.com/reference/overview
"""

import requests
import time
import logging
from typing import Dict, Optional, Any
from config.config import Config

logger = logging.getLogger(__name__)


class VirusTotalClient:
    """Client for VirusTotal API v3."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or Config.VT_API_KEY
        self.base_url = Config.VT_BASE_URL
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.last_request_time = 0
        self.min_request_interval = 15  # seconds (4 requests/minute for free tier)

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
                logger.warning("VirusTotal rate limit exceeded. Waiting 60s...")
                time.sleep(60)
                return self._make_request(endpoint, params)

            response.raise_for_status()
            return response.json()

        except requests.exceptions.Timeout:
            logger.error(f"Timeout querying VirusTotal: {endpoint}")
            return {"error": "Request timeout", "status": "failed"}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for VirusTotal: {e}")
            return {"error": str(e), "status": "failed"}

    def query_ip(self, ip: str) -> Dict[str, Any]:
        """
        Query VirusTotal for IP address reputation.

        Args:
            ip: IP address to query

        Returns:
            Enriched data with malicious score and analysis stats
        """
        endpoint = f"{self.base_url}/ip_addresses/{ip}"
        data = self._make_request(endpoint)

        if "error" in data:
            return {
                "source": "virustotal",
                "ioc": ip,
                "type": "ip",
                "status": "error",
                "error": data.get("error", "Unknown error")
            }

        attributes = data.get("data", {}).get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})

        # Calculate malicious ratio
        total = sum(last_analysis.values()) if last_analysis else 0
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)

        malicious_ratio = (malicious + suspicious) / total if total > 0 else 0

        return {
            "source": "virustotal",
            "ioc": ip,
            "type": "ip",
            "status": "success",
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": last_analysis.get("harmless", 0),
            "undetected_count": last_analysis.get("undetected", 0),
            "total_engines": total,
            "malicious_ratio": round(malicious_ratio, 4),
            "reputation_score": attributes.get("reputation", 0),
            "country": attributes.get("country", "unknown"),
            "as_owner": attributes.get("as_owner", "unknown"),
            "last_analysis_date": attributes.get("last_analysis_date", "unknown"),
            "raw_data": data  # Keep raw for advanced use
        }

    def query_domain(self, domain: str) -> Dict[str, Any]:
        """
        Query VirusTotal for domain reputation.

        Args:
            domain: Domain to query

        Returns:
            Enriched data with malicious score and analysis stats
        """
        endpoint = f"{self.base_url}/domains/{domain}"
        data = self._make_request(endpoint)

        if "error" in data:
            return {
                "source": "virustotal",
                "ioc": domain,
                "type": "domain",
                "status": "error",
                "error": data.get("error", "Unknown error")
            }

        attributes = data.get("data", {}).get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})

        total = sum(last_analysis.values()) if last_analysis else 0
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        malicious_ratio = (malicious + suspicious) / total if total > 0 else 0

        return {
            "source": "virustotal",
            "ioc": domain,
            "type": "domain",
            "status": "success",
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": last_analysis.get("harmless", 0),
            "undetected_count": last_analysis.get("undetected", 0),
            "total_engines": total,
            "malicious_ratio": round(malicious_ratio, 4),
            "reputation_score": attributes.get("reputation", 0),
            "creation_date": attributes.get("creation_date", "unknown"),
            "last_analysis_date": attributes.get("last_analysis_date", "unknown"),
            "raw_data": data
        }

    def query_filehash(self, file_hash: str) -> Dict[str, Any]:
        """
        Query VirusTotal for file hash reputation.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            Enriched data with detection stats
        """
        endpoint = f"{self.base_url}/files/{file_hash}"
        data = self._make_request(endpoint)

        if "error" in data:
            return {
                "source": "virustotal",
                "ioc": file_hash,
                "type": "filehash",
                "status": "error",
                "error": data.get("error", "Unknown error")
            }

        attributes = data.get("data", {}).get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})

        total = sum(last_analysis.values()) if last_analysis else 0
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        malicious_ratio = (malicious + suspicious) / total if total > 0 else 0

        return {
            "source": "virustotal",
            "ioc": file_hash,
            "type": "filehash",
            "status": "success",
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": last_analysis.get("harmless", 0),
            "undetected_count": last_analysis.get("undetected", 0),
            "total_engines": total,
            "malicious_ratio": round(malicious_ratio, 4),
            "file_type": attributes.get("type_description", "unknown"),
            "file_size": attributes.get("size", 0),
            "meaningful_name": attributes.get("meaningful_name", "unknown"),
            "last_analysis_date": attributes.get("last_analysis_date", "unknown"),
            "raw_data": data
        }

    def query_url(self, url: str) -> Dict[str, Any]:
        """
        Query VirusTotal for URL reputation.

        Args:
            url: URL to query

        Returns:
            Enriched data with detection stats
        """
        import base64
        # VT requires URL to be base64 encoded
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"{self.base_url}/urls/{url_id}"
        data = self._make_request(endpoint)

        if "error" in data:
            return {
                "source": "virustotal",
                "ioc": url,
                "type": "url",
                "status": "error",
                "error": data.get("error", "Unknown error")
            }

        attributes = data.get("data", {}).get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})

        total = sum(last_analysis.values()) if last_analysis else 0
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        malicious_ratio = (malicious + suspicious) / total if total > 0 else 0

        return {
            "source": "virustotal",
            "ioc": url,
            "type": "url",
            "status": "success",
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": last_analysis.get("harmless", 0),
            "undetected_count": last_analysis.get("undetected", 0),
            "total_engines": total,
            "malicious_ratio": round(malicious_ratio, 4),
            "last_analysis_date": attributes.get("last_analysis_date", "unknown"),
            "raw_data": data
        }
