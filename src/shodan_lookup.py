"""
Shodan API integration module.

Uses Shodan API for host intelligence.
API docs: https://developer.shodan.io/api
"""

import requests
import time
import logging
from typing import Dict, Optional, Any, List
from config.config import Config

logger = logging.getLogger(__name__)


class ShodanClient:
    """Client for Shodan API."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or Config.SHODAN_API_KEY
        self.base_url = Config.SHODAN_BASE_URL
        self.session = requests.Session()
        self.last_request_time = 0
        self.min_request_interval = 1.0  # Shodan is generally more lenient

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

        # Add API key to params
        request_params = params or {}
        request_params["key"] = self.api_key

        try:
            response = self.session.get(endpoint, params=request_params, timeout=30)

            if response.status_code == 429:
                logger.warning("Shodan rate limit exceeded. Waiting 60s...")
                time.sleep(60)
                return self._make_request(endpoint, params)

            response.raise_for_status()
            return response.json()

        except requests.exceptions.Timeout:
            logger.error(f"Timeout querying Shodan: {endpoint}")
            return {"error": "Request timeout", "status": "failed"}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for Shodan: {e}")
            return {"error": str(e), "status": "failed"}

    def query_ip(self, ip: str, history: bool = False) -> Dict[str, Any]:
        """
        Query Shodan for host information.

        Args:
            ip: IP address to query
            history: Include historical data (up to 90 days)

        Returns:
            Enriched data with open ports, services, and host info
        """
        endpoint = f"{self.base_url}/shodan/host/{ip}"
        params = {"history": history}

        data = self._make_request(endpoint, params)

        if "error" in data:
            return {
                "source": "shodan",
                "ioc": ip,
                "type": "ip",
                "status": "error",
                "error": data.get("error", "Unknown error")
            }

        # Extract open ports and services
        ports: List[int] = []
        services: List[Dict[str, Any]] = []
        vulns: List[str] = []

        for banner in data.get("data", []):
            port = banner.get("port")
            if port and port not in ports:
                ports.append(port)

            service_info = {
                "port": port,
                "transport": banner.get("transport", "unknown"),
                "product": banner.get("product", "unknown"),
                "version": banner.get("version", "unknown"),
                "cpe": banner.get("cpe", []),
            }
            services.append(service_info)

            # Check for vulnerabilities
            if "vulns" in banner:
                vulns.extend(banner["vulns"].keys())

        # Risk scoring based on exposed services
        risk_indicators = []

        high_risk_ports = {22, 23, 3389, 445, 135, 3306, 5432, 6379, 27017, 9200}
        medium_risk_ports = {21, 25, 53, 110, 143, 993, 995, 8080, 8443}

        exposed_high_risk = set(ports) & high_risk_ports
        exposed_medium_risk = set(ports) & medium_risk_ports

        if exposed_high_risk:
            risk_indicators.append(f"High-risk ports exposed: {sorted(exposed_high_risk)}")
        if exposed_medium_risk:
            risk_indicators.append(f"Medium-risk ports exposed: {sorted(exposed_medium_risk)}")
        if vulns:
            risk_indicators.append(f"Known vulnerabilities found: {len(vulns)}")
        if data.get("tags"):
            risk_indicators.append(f"Tags: {data.get('tags')}")

        return {
            "source": "shodan",
            "ioc": ip,
            "type": "ip",
            "status": "success",
            "hostnames": data.get("hostnames", []),
            "organization": data.get("org", "unknown"),
            "isp": data.get("isp", "unknown"),
            "country_code": data.get("country_code", "unknown"),
            "country_name": data.get("country_name", "unknown"),
            "city": data.get("city", "unknown"),
            "os": data.get("os", "unknown"),
            "ports": sorted(ports),
            "services": services,
            "vulnerabilities": list(set(vulns)),
            "tags": data.get("tags", []),
            "last_update": data.get("last_update", "unknown"),
            "risk_indicators": risk_indicators,
            "raw_data": data
        }

    def get_api_info(self) -> Dict[str, Any]:
        """Get current API usage information."""
        endpoint = f"{self.base_url}/api-info"
        return self._make_request(endpoint)
