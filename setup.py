"""
LLMGuardian setup configuration.
"""

from setuptools import setup, find_packages
from pathlib import Path
import re

# Read the version from __init__.py
def get_version():
    init_file = Path("src/llmguardian/__init__.py").read_text()
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", init_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")

# Read the long description from README.md
long_description = Path("README.md").read_text(encoding="utf-8")

# Core dependencies - defined in pyproject.toml but listed here for setup.py compatibility
CORE_DEPS = [
    "click>=8.1.0",
    "rich>=13.0.0",
    "pyyaml>=6.0.1",
    "psutil>=5.9.0",
    "python-json-logger>=2.0.7",
    "typing-extensions>=4.5.0",
    "pyjwt>=2.8.0",
    "cryptography>=41.0.0",
    "requests>=2.31.0",
    "prometheus-client>=0.17.0",
    "statsd>=4.0.1",
]

DEV_DEPS = [
    "pytest>=7.4.0",
    "pytest-cov>=4.1.0",
    "pytest-mock>=3.11.1",
    "black>=23.9.1",
    "flake8>=6.1.0",
    "mypy>=1.5.1",
    "isort>=5.12.0",
]

TEST_DEPS = [
    "pytest>=7.4.0",
    "pytest-cov>=4.1.0",
    "pytest-mock>=3.11.1",
]

DASHBOARD_DEPS = [
    "streamlit>=1.24.0",
    "plotly>=5.15.0",
    "pandas>=2.0.0",
    "numpy>=1.24.0",
]

API_DEPS = [
    "fastapi>=0.100.0",
    "uvicorn>=0.23.0",
]

setup(
    name="llmguardian",
    version=get_version(),
    author="dewitt4",
    author_email="",  # Add your email if you want
    description="A comprehensive security tool for LLM applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/dewitt4/LLMGuardian",
    project_urls={
        "Bug Tracker": "https://github.com/dewitt4/LLMGuardian/issues",
        "Documentation": "https://github.com/dewitt4/LLMGuardian/wiki",
        "Source Code": "https://github.com/dewitt4/LLMGuardian",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    keywords=["llm", "security", "ai", "machine-learning", "prompt-injection", "cybersecurity"],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    
    # Core dependencies
    install_requires=CORE_DEPS,
    
    # Optional/extra dependencies
    extras_require={
        "dev": DEV_DEPS,
        "test": TEST_DEPS,
        "dashboard": DASHBOARD_DEPS,
        "api": API_DEPS,
        "all": DEV_DEPS + DASHBOARD_DEPS + API_DEPS,
    },
    
    # Entry points for CLI
    entry_points={
        "console_scripts": [
            "llmguardian=llmguardian.cli.main:cli",
        ],
    },
    
    # Include package data
    include_package_data=True,
    package_data={
        "llmguardian": [
            "data/*.json",
            "data/*.yaml",
        ],
    },
    
    # Additional metadata
    platforms=["any"],
    zip_safe=False,
)
