#!/bin/bash
# setup_project.sh
# Script to set up the LLMGuardian project structure

# Create main project directory
mkdir -p LLMGuardian
cd LLMGuardian

# Create GitHub directory
mkdir -p .github

# Create source directory structure
mkdir -p src/llmguardian/{cli,scanners,defenders,monitors,api,utils,core}
touch src/llmguardian/__init__.py
touch src/llmguardian/cli/__init__.py
touch src/llmguardian/scanners/__init__.py
touch src/llmguardian/defenders/__init__.py
touch src/llmguardian/monitors/__init__.py
touch src/llmguardian/api/__init__.py
touch src/llmguardian/utils/__init__.py
touch src/llmguardian/core/__init__.py

# Create requirements directory and files
mkdir -p requirements
echo "# Core dependencies
click>=8.1.0
rich>=13.0.0
pathlib>=1.0.1
dataclasses>=0.6
typing>=3.7.4
enum34>=1.1.10" > requirements/base.txt

echo "-r base.txt
pytest>=7.0.0
pytest-cov>=4.0.0
black>=23.0.0
flake8>=6.0.0
mypy>=1.0.0
isort>=5.0.0" > requirements/dev.txt

echo "-r base.txt
pytest>=7.0.0
pytest-cov>=4.0.0
pytest-mock>=3.10.0
coverage>=7.2.0" > requirements/test.txt

echo "-r requirements/base.txt" > requirements.txt

# Create test directory structure
mkdir -p tests/{unit,integration,security}
touch tests/__init__.py
touch tests/conftest.py

# Create documentation directory
mkdir -p docs/{api,guides,security,examples}

# Create other necessary files
touch setup.py
touch README.md
touch CONTRIBUTING.md
touch LICENSE
touch .gitignore

# Create basic .gitignore content
echo "# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
env/
ENV/

# IDE
.idea/
.vscode/
*.swp
*.swo

# Testing
.coverage
htmlcov/
.tox/
.pytest_cache/

# Distribution
*.tar.gz
*.whl

# Logs
*.log
" > .gitignore

echo "Project structure created successfully!"
