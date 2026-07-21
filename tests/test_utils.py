"""Tests for utility functions."""
import pytest
from src.utils import classify_ioc, is_private_ip, deduplicate_iocs, SimpleCache


def test_classify_ip():
    assert classify_ioc("8.8.8.8") == "ip"
    assert classify_ioc("2001:db8::1") == "ip"


def test_classify_domain():
    assert classify_ioc("google.com") == "domain"
    assert classify_ioc("sub.example.co.uk") == "domain"


def test_classify_hash():
    assert classify_ioc("44d88612fea8a8f36de82e1278abb02f") == "filehash"  # MD5
    assert classify_ioc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "filehash"  # SHA256


def test_private_ip():
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("8.8.8.8") is False


def test_deduplicate_iocs():
    iocs = [
        {"ioc": "8.8.8.8", "type": "ip"},
        {"ioc": "8.8.8.8", "type": "ip"},
        {"ioc": "google.com", "type": "domain"}
    ]
    result = deduplicate_iocs(iocs)
    assert len(result) == 2
    assert result[0]["ioc"] == "8.8.8.8"
    assert result[1]["ioc"] == "google.com"


def test_cache():
    cache = SimpleCache()
    cache.set("test_key", {"data": "value"})
    assert cache.get("test_key") == {"data": "value"}
    cache.clear()
    assert cache.get("test_key") is None
