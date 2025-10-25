"""
LLMGuardian setup configuration.
"""

from setuptools import setup, find_packages
from pathlib import Path
import re

# Read the content of requirements files
def read_requirements(filename):
    with open(Path("requirements") / filename) as f:
        return [line.strip() for line in f
                if line.strip() and not line.startswith(('#', '-r'))]

# Read the version from __init__.py
def get_version():
    init_file = Path("src/llmguardian/__init__.py").read_text()
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", init_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")

# Read the long description from README.md
long_description = Path("README.md").read_text(encoding="utf-8")

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
    keywords="llm, security, ai, machine-learning, prompt-injection, cybersecurity",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    
    # Core dependencies
    install_requires=read_requirements("base.txt"),
    
    # Optional/extra dependencies
    extras_require={
        "dev": read_requirements("dev.txt"),
        "test": read_requirements("test.txt"),
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
    
    # Testing
    test_suite="tests",
)
