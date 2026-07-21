"""
Configuration module for IOC Triage Platform v2.0.
Handles environment variables, API keys, rate limits, and application settings.
"""

import os
import logging
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=env_path)


class Config:
    """Application configuration class with validation."""

    # Base paths
    BASE_DIR = Path(__file__).parent.parent
    REPORTS_DIR = BASE_DIR / os.getenv("REPORTS_DIR", "reports")
    INPUT_DIR = BASE_DIR / os.getenv("INPUT_DIR", "input")
    CACHE_DIR = BASE_DIR / os.getenv("CACHE_DIR", ".cache")

    # API Keys
    VT_API_KEY = os.getenv("VT_API_KEY")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

    # Rate limiting (requests per minute)
    VT_RATE_LIMIT = int(os.getenv("VT_RATE_LIMIT_PER_MINUTE", "4"))
    ABUSEIPDB_RATE_LIMIT = int(os.getenv("ABUSEIPDB_RATE_LIMIT_PER_MINUTE", "40"))
    SHODAN_RATE_LIMIT = int(os.getenv("SHODAN_RATE_LIMIT_PER_MINUTE", "60"))

    # Retry configuration
    MAX_RETRY_ATTEMPTS = int(os.getenv("MAX_RETRY_ATTEMPTS", "3"))
    RETRY_BASE_DELAY = float(os.getenv("RETRY_BASE_DELAY", "2.0"))

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    # Scoring weights (must sum to 1.0)
    VT_WEIGHT = float(os.getenv("VT_WEIGHT", "0.4"))
    ABUSEIPDB_WEIGHT = float(os.getenv("ABUSEIPDB_WEIGHT", "0.4"))
    SHODAN_WEIGHT = float(os.getenv("SHODAN_WEIGHT", "0.2"))

    # Cache settings
    CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "86400"))

    # Case management
    CASE_DB_PATH = BASE_DIR / os.getenv("CASE_DB_PATH", "cases.db")

    # API Endpoints
    VT_BASE_URL = "https://www.virustotal.com/api/v3"
    ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
    SHODAN_BASE_URL = "https://api.shodan.io"

    @classmethod
    def validate(cls):
        """Validate that required configuration is present."""
        missing = []

        if not cls.VT_API_KEY:
            missing.append("VT_API_KEY")
        if not cls.ABUSEIPDB_API_KEY:
            missing.append("ABUSEIPDB_API_KEY")
        if not cls.SHODAN_API_KEY:
            missing.append("SHODAN_API_KEY")

        if missing:
            raise ValueError(
                f"Missing required API keys: {', '.join(missing)}. "
                "Please set them in your .env file."
            )

        # Validate weights sum to 1.0
        total_weight = cls.VT_WEIGHT + cls.ABUSEIPDB_WEIGHT + cls.SHODAN_WEIGHT
        if abs(total_weight - 1.0) > 0.001:
            raise ValueError(
                f"Scoring weights must sum to 1.0, got {total_weight}"
            )

        # Ensure directories exist
        cls.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        cls.INPUT_DIR.mkdir(parents=True, exist_ok=True)
        cls.CACHE_DIR.mkdir(parents=True, exist_ok=True)

        return True

    @classmethod
    def setup_logging(cls):
        """Configure application logging."""
        logging.basicConfig(
            level=getattr(logging, cls.LOG_LEVEL),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(cls.BASE_DIR / "ioc_triage.log")
            ]
        )
        return logging.getLogger(__name__)
