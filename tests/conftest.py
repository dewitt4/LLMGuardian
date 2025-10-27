"""
tests/conftest.py - Pytest configuration and shared fixtures
"""

import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest

from llmguardian.core.config import Config
from llmguardian.core.logger import SecurityLogger


@pytest.fixture(scope="session")
def test_data_dir() -> Path:
    """Get test data directory"""
    return Path(__file__).parent / "data"


@pytest.fixture(scope="session")
def test_config() -> Dict[str, Any]:
    """Load test configuration"""
    config_path = Path(__file__).parent / "config" / "test_config.json"
    with open(config_path) as f:
        return json.load(f)


@pytest.fixture
def security_logger():
    """Create a security logger for testing"""
    return SecurityLogger(log_path=str(Path(__file__).parent / "logs"))


@pytest.fixture
def config(test_config):
    """Create a configuration instance for testing"""
    return Config(config_data=test_config)


@pytest.fixture
def temp_dir(tmpdir):
    """Create a temporary directory for test files"""
    return Path(tmpdir)


@pytest.fixture
def sample_text_data():
    """Sample text data for testing"""
    return {
        "clean": "This is a clean text without sensitive information.",
        "with_pii": "Contact john.doe@example.com or call 123-456-7890",
        "with_phi": "Patient medical record #12345: Diagnosis notes",
        "with_financial": "Credit card: 4111-1111-1111-1111",
        "with_credentials": "API key: xyz123abc",
        "with_location": "IP: 192.168.1.1, GPS: 37.7749, -122.4194",
        "mixed": """
            Name: John Doe
            Email: john.doe@example.com
            SSN: 123-45-6789
            Credit Card: 4111-1111-1111-1111
            Medical ID: PHI123456
            Password: secret123
        """,
    }


@pytest.fixture
def sample_vectors():
    """Sample vector data for testing"""
    return {
        "clean": [0.1, 0.2, 0.3],
        "suspicious": [0.9, 0.8, 0.7],
        "anomalous": [10.0, -10.0, 5.0],
    }


@pytest.fixture
def test_rules():
    """Test privacy rules"""
    return {
        "test_rule_1": {
            "name": "Test Rule 1",
            "category": "PII",
            "level": "CONFIDENTIAL",
            "patterns": [r"\b\w+@\w+\.\w+\b"],
            "actions": ["mask"],
        },
        "test_rule_2": {
            "name": "Test Rule 2",
            "category": "PHI",
            "level": "RESTRICTED",
            "patterns": [r"medical.*\d+"],
            "actions": ["block", "alert"],
        },
    }


@pytest.fixture(autouse=True)
def setup_teardown():
    """Setup and teardown for each test"""
    # Setup
    test_log_dir = Path(__file__).parent / "logs"
    test_log_dir.mkdir(exist_ok=True)

    yield

    # Teardown
    for f in test_log_dir.glob("*.log"):
        f.unlink()


@pytest.fixture
def mock_security_logger(mocker):
    """Create a mocked security logger"""
    return mocker.patch("llmguardian.core.logger.SecurityLogger")
