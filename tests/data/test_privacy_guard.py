"""
tests/data/test_privacy_guard.py - Test cases for privacy protection functionality
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch
from llmguardian.data.privacy_guard import (
    PrivacyGuard,
    PrivacyRule,
    PrivacyLevel,
    DataCategory,
    PrivacyCheck
)
from llmguardian.core.exceptions import SecurityError

@pytest.fixture
def security_logger():
    return Mock()

@pytest.fixture
def privacy_guard(security_logger):
    return PrivacyGuard(security_logger=security_logger)

@pytest.fixture
def test_data():
    return {
        "pii": {
            "email": "test@example.com",
            "ssn": "123-45-6789",
            "phone": "123-456-7890"
        },
        "phi": {
            "medical_record": "Patient health record #12345",
            "diagnosis": "Test diagnosis for patient"
        },
        "financial": {
            "credit_card": "4111-1111-1111-1111",
            "bank_account": "123456789"
        },
        "credentials": {
            "password": "password=secret123",
            "api_key": "api_key=abc123xyz"
        },
        "location": {
            "ip": "192.168.1.1",
            "coords": "latitude: 37.7749, longitude: -122.4194"
        }
    }

class TestPrivacyGuard:
    def test_initialization(self, privacy_guard):
        """Test privacy guard initialization"""
        assert privacy_guard.rules is not None
        assert privacy_guard.compiled_patterns is not None
        assert len(privacy_guard.check_history) == 0

    def test_basic_pii_detection(self, privacy_guard, test_data):
        """Test detection of basic PII"""
        result = privacy_guard.check_privacy(test_data["pii"])
        assert not result.compliant
        assert any(v["category"] == DataCategory.PII.value for v in result.violations)
        assert result.risk_level in ["medium", "high"]

    def test_phi_detection(self, privacy_guard, test_data):
        """Test detection of PHI"""
        result = privacy_guard.check_privacy(test_data["phi"])
        assert not result.compliant
        assert any(v["category"] == DataCategory.PHI.value for v in result.violations)
        assert result.risk_level in ["high", "critical"]

    def test_financial_data_detection(self, privacy_guard, test_data):
        """Test detection of financial data"""
        result = privacy_guard.check_privacy(test_data["financial"])
        assert not result.compliant
        assert any(v["category"] == DataCategory.FINANCIAL.value for v in result.violations)

    def test_credential_detection(self, privacy_guard, test_data):
        """Test detection of credentials"""
        result = privacy_guard.check_privacy(test_data["credentials"])
        assert not result.compliant
        assert any(v["category"] == DataCategory.CREDENTIALS.value for v in result.violations)
        assert result.risk_level == "critical"

    def test_location_data_detection(self, privacy_guard, test_data):
        """Test detection of location data"""
        result = privacy_guard.check_privacy(test_data["location"])
        assert not result.compliant
        assert any(v["category"] == DataCategory.LOCATION.value for v in result.violations)

    def test_privacy_enforcement(self, privacy_guard, test_data):
        """Test privacy enforcement"""
        enforced = privacy_guard.enforce_privacy(
            test_data["pii"],
            PrivacyLevel.CONFIDENTIAL
        )
        assert test_data["pii"]["email"] not in enforced
        assert test_data["pii"]["ssn"] not in enforced
        assert "***" in enforced

    def test_custom_rule_addition(self, privacy_guard):
        """Test adding custom privacy rule"""
        custom_rule = PrivacyRule(
            name="custom_test",
            category=DataCategory.PII,
            level=PrivacyLevel.CONFIDENTIAL,
            patterns=[r"test\d{3}"],
            actions=["mask"]
        )
        privacy_guard.add_rule(custom_rule)
        
        test_content = "test123 is a test string"
        result = privacy_guard.check_privacy(test_content)
        assert not result.compliant
        assert any(v["rule"] == "custom_test" for v in result.violations)

    def test_rule_removal(self, privacy_guard):
        """Test rule removal"""
        initial_rule_count = len(privacy_guard.rules)
        privacy_guard.remove_rule("pii_basic")
        assert len(privacy_guard.rules) == initial_rule_count - 1
        assert "pii_basic" not in privacy_guard.rules

    def test_rule_update(self, privacy_guard):
        """Test rule update"""
        updates = {
            "patterns": [r"updated\d+"],
            "actions": ["log"]
        }
        privacy_guard.update_rule("pii_basic", updates)
        assert privacy_guard.rules["pii_basic"].patterns == updates["patterns"]
        assert privacy_guard.rules["pii_basic"].actions == updates["actions"]

    def test_privacy_stats(self, privacy_guard, test_data):
        """Test privacy statistics generation"""
        # Generate some violations
        privacy_guard.check_privacy(test_data["pii"])
        privacy_guard.check_privacy(test_data["phi"])
        
        stats = privacy_guard.get_privacy_stats()
        assert stats["total_checks"] == 2
        assert stats["violation_count"] > 0
        assert len(stats["risk_levels"]) > 0
        assert len(stats["categories"]) > 0

    def test_trend_analysis(self, privacy_guard, test_data):
        """Test trend analysis"""
        # Generate historical data
        for _ in range(3):
            privacy_guard.check_privacy(test_data["pii"])
            privacy_guard.check_privacy(test_data["phi"])
        
        trends = privacy_guard.analyze_trends()
        assert "violation_frequency" in trends
        assert "risk_distribution" in trends
        assert "category_trends" in trends

    def test_configuration_validation(self, privacy_guard):
        """Test configuration validation"""
        validation = privacy_guard.validate_configuration()
        assert validation["valid"]
        assert "statistics" in validation
        assert validation["statistics"]["total_rules"] > 0

    def test_privacy_report(self, privacy_guard, test_data):
        """Test privacy report generation"""
        # Generate some data
        privacy_guard.check_privacy(test_data["pii"])
        privacy_guard.check_privacy(test_data["phi"])
        
        report = privacy_guard.generate_privacy_report()
        assert "summary" in report
        assert "risk_analysis" in report
        assert "category_analysis" in report
        assert "recommendations" in report

    def test_error_handling(self, privacy_guard):
        """Test error handling"""
        with pytest.raises(SecurityError):
            privacy_guard.check_privacy(None)

    def test_batch_processing(self, privacy_guard, test_data):
        """Test batch privacy checking"""
        items = [
            test_data["pii"],
            test_data["phi"],
            test_data["financial"]
        ]
        results = privacy_guard.batch_check_privacy(items)
        assert results["compliant_items"] >= 0
        assert results["non_compliant_items"] > 0
        assert "overall_risk_level" in results

    def test_privacy_impact_simulation(self, privacy_guard, test_data):
        """Test privacy impact simulation"""
        simulation_config = {
            "scenarios": [
                {
                    "name": "add_pii",
                    "type": "add_data",
                    "data": "email: new@example.com"
                }
            ]
        }
        results = privacy_guard.simulate_privacy_impact(
            test_data["pii"],
            simulation_config
        )
        assert "baseline" in results
        assert "simulations" in results

    @pytest.mark.asyncio
    async def test_monitoring(self, privacy_guard):
        """Test privacy monitoring"""
        callback_called = False
        
        def test_callback(issues):
            nonlocal callback_called
            callback_called = True
        
        # Start monitoring
        privacy_guard.monitor_privacy_compliance(
            interval=1,
            callback=test_callback
        )
        
        # Generate some violations
        privacy_guard.check_privacy({"sensitive": "test@example.com"})
        
        # Wait for monitoring cycle
        await asyncio.sleep(2)
        
        privacy_guard.stop_monitoring()
        assert callback_called

    def test_context_handling(self, privacy_guard, test_data):
        """Test context-aware privacy checking"""
        context = {
            "source": "test",
            "environment": "development",
            "exceptions": ["verified_public_email"]
        }
        result = privacy_guard.check_privacy(test_data["pii"], context)
        assert "context" in result.metadata

    @pytest.mark.parametrize("risk_level,expected", [
        ("low", "low"),
        ("medium", "medium"),
        ("high", "high"),
        ("critical", "critical")
    ])
    def test_risk_level_comparison(self, privacy_guard, risk_level, expected):
        """Test risk level comparison"""
        other_level = "low"
        comparison = privacy_guard._compare_risk_levels(risk_level, other_level)
        assert comparison >= 0 if risk_level != "low" else comparison == 0

if __name__ == "__main__":
    pytest.main([__file__])