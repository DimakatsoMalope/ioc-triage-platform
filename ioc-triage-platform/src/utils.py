"""
Utility functions for IOC Triage Platform.
"""

import re
import ipaddress
import hashlib
import json
import time
import os
from typing import Optional, Literal, Dict, Any, List, Set
from urllib.parse import urlparse
from pathlib import Path
from functools import wraps


def classify_ioc(ioc: str) -> Optional[Literal["ip", "domain", "filehash", "url", "unknown"]]:
    """Automatically classify an IOC type."""
    ioc = ioc.strip()

    # Check for IP address (IPv4 or IPv6)
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass

    # Check for URL
    if ioc.startswith(("http://", "https://")):
        return "url"

    # Check for file hash (MD5, SHA1, SHA256)
    if re.match(r'^[a-fA-F0-9]{32}$', ioc):
        return "filehash"
    if re.match(r'^[a-fA-F0-9]{40}$', ioc):
        return "filehash"
    if re.match(r'^[a-fA-F0-9]{64}$', ioc):
        return "filehash"

    # Check for domain
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])$'
    )
    if domain_pattern.match(ioc) and "." in ioc:
        return "domain"

    return "unknown"


def extract_domain_from_url(url: str) -> str:
    """Extract domain from a URL."""
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return False


def format_timestamp() -> str:
    """Get current timestamp in ISO format."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate a string with ellipsis."""
    if len(s) <= max_length:
        return s
    return s[:max_length-3] + "..."


def safe_get(data: dict, *keys, default=None):
    """Safely navigate nested dictionaries."""
    for key in keys:
        if isinstance(data, dict) and key in data:
            data = data[key]
        else:
            return default
    return data


def deduplicate_iocs(iocs: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    Deduplicate IOCs while preserving order.

    Args:
        iocs: List of IOC dicts with 'ioc' and 'type' keys

    Returns:
        Deduplicated list
    """
    seen: Set[str] = set()
    unique = []
    for ioc_data in iocs:
        key = f"{ioc_data['ioc'].lower()}:{ioc_data['type']}"
        if key not in seen:
            seen.add(key)
            unique.append(ioc_data)
    return unique


class SimpleCache:
    """
    Simple file-based cache for API responses.

    Caches enrichment results to avoid redundant API calls.
    TTL configurable (default 24 hours).
    """

    def __init__(self, cache_dir: Path = None, ttl_seconds: int = 86400):
        self.cache_dir = cache_dir or Path(".cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_seconds

    def _get_cache_path(self, key: str) -> Path:
        """Generate cache file path from key."""
        safe_key = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{safe_key}.json"

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached value if not expired."""
        cache_path = self._get_cache_path(key)

        if not cache_path.exists():
            return None

        try:
            with open(cache_path, "r") as f:
                cached = json.load(f)

            # Check TTL
            if time.time() - cached.get("_cached_at", 0) > self.ttl_seconds:
                cache_path.unlink()
                return None

            return cached.get("data")
        except (json.JSONDecodeError, KeyError):
            cache_path.unlink()
            return None

    def set(self, key: str, data: Dict[str, Any]):
        """Cache value with timestamp."""
        cache_path = self._get_cache_path(key)
        cached = {
            "_cached_at": time.time(),
            "data": data
        }
        with open(cache_path, "w") as f:
            json.dump(cached, f)

    def clear(self):
        """Clear all cached entries."""
        for f in self.cache_dir.glob("*.json"):
            f.unlink()

    def stats(self) -> Dict[str, int]:
        """Return cache statistics."""
        files = list(self.cache_dir.glob("*.json"))
        total_size = sum(f.stat().st_size for f in files)
        return {
            "entries": len(files),
            "total_size_bytes": total_size
        }
