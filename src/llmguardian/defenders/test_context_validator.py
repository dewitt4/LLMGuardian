"""
tests/defenders/test_context_validator.py - Tests for context validation
"""

import pytest
from datetime import datetime, timedelta
from llmguardian.defenders.context_validator import ContextValidator, ValidationResult
from llmguardian.core.exceptions import ValidationError


@pytest.fixture
def validator():
    return ContextValidator()


@pytest.fixture
def valid_context():
    return {
        "user_id": "test_user",
        "session_id": "test_session",
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": "123",
        "metadata": {"source": "test", "version": "1.0"},
    }


def test_valid_context(validator, valid_context):
    result = validator.validate_context(valid_context)
    assert result.is_valid
    assert not result.errors
    assert result.modified_context == valid_context


def test_missing_required_fields(validator):
    context = {"user_id": "test_user", "timestamp": datetime.utcnow().isoformat()}
    result = validator.validate_context(context)
    assert not result.is_valid
    assert "Missing required fields" in result.errors[0]


def test_forbidden_fields(validator, valid_context):
    context = valid_context.copy()
    context["password"] = "secret123"
    result = validator.validate_context(context)
    assert not result.is_valid
    assert "Forbidden fields present" in result.errors[0]
    assert "password" not in result.modified_context


def test_context_age(validator, valid_context):
    old_context = valid_context.copy()
    old_context["timestamp"] = (datetime.utcnow() - timedelta(hours=2)).isoformat()
    result = validator.validate_context(old_context)
    assert not result.is_valid
    assert "Context too old" in result.errors[0]


def test_context_depth(validator, valid_context):
    deep_context = valid_context.copy()
    current = deep_context
    for i in range(10):
        current["nested"] = {}
        current = current["nested"]
    result = validator.validate_context(deep_context)
    assert not result.is_valid
    assert "Context exceeds max depth" in result.errors[0]


def test_checksum_verification(validator, valid_context):
    previous_context = valid_context.copy()
    modified_context = valid_context.copy()
    modified_context["user_id"] = "different_user"
    result = validator.validate_context(modified_context, previous_context)
    assert not result.is_valid
    assert "Context checksum mismatch" in result.errors[0]


def test_update_rule(validator):
    validator.update_rule({"max_age": 7200})
    old_context = {
        "user_id": "test_user",
        "session_id": "test_session",
        "timestamp": (datetime.utcnow() - timedelta(hours=1.5)).isoformat(),
    }
    result = validator.validate_context(old_context)
    assert result.is_valid


def test_exception_handling(validator):
    with pytest.raises(ValidationError):
        validator.validate_context({"timestamp": "invalid_date"})


def test_metadata_generation(validator, valid_context):
    result = validator.validate_context(valid_context)
    assert "validation_time" in result.metadata
    assert "original_size" in result.metadata
    assert "modified_size" in result.metadata
    assert "changes" in result.metadata
