"""
tests/utils/test_utils.py - Testing utilities and helpers
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
import numpy as np

def load_test_data(filename: str) -> Dict[str, Any]:
    """Load test data from JSON file"""
    data_path = Path(__file__).parent.parent / "data" / filename
    with open(data_path) as f:
        return json.load(f)

def compare_privacy_results(result1: Dict[str, Any], 
                          result2: Dict[str, Any]) -> bool:
    """Compare two privacy check results"""
    # Compare basic fields
    if result1["compliant"] != result2["compliant"]:
        return False
    if result1["risk_level"] != result2["risk_level"]:
        return False
    
    #