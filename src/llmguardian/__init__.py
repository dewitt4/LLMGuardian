"""
LLMGuardian - A comprehensive security tool for LLM applications.
"""

__title__ = "llmguardian"
__version__ = "1.4.0"
__author__ = "dewitt4"
__license__ = "Apache-2.0"

from typing import List, Dict, Optional

# Package level imports
from .scanners.prompt_injection_scanner import PromptInjectionScanner
from .core.config import Config
from .core.logger import setup_logging

# Initialize logging
setup_logging()

# Version information tuple
VERSION = tuple(map(int, __version__.split(".")))


def get_version() -> str:
    """Return the version string."""
    return __version__


def get_scanner() -> PromptInjectionScanner:
    """Get a configured instance of the prompt injection scanner."""
    return PromptInjectionScanner()


# Export commonly used classes
__all__ = [
    "PromptInjectionScanner",
    "Config",
    "get_version",
    "get_scanner",
]
