---
title: LLMGuardian
emoji: 🛡️
colorFrom: blue
colorTo: purple
sdk: gradio
sdk_version: "4.44.1"
app_file: app.py
pinned: false
license: apache-2.0
---

# LLMGuardian

[![CI](https://github.com/dewitt4/llmguardian/actions/workflows/ci.yml/badge.svg)](https://github.com/dewitt4/llmguardian/actions/workflows/ci.yml)
[![Security Scan](https://github.com/dewitt4/llmguardian/actions/workflows/security-scan.yml/badge.svg)](https://github.com/dewitt4/llmguardian/actions/workflows/security-scan.yml)
[![Docker Build](https://github.com/dewitt4/llmguardian/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/dewitt4/llmguardian/actions/workflows/docker-publish.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Comprehensive LLM AI Model protection toolset aligned to addressing OWASP vulnerabilities in Large Language Models.

 LLMGuardian is a cybersecurity toolset designed to protect production Generative AI applications by addressing the OWASP LLM Top 10 vulnerabilities. This toolset offers comprehensive features like Prompt Injection Detection, Data Leakage Prevention, and a Streamlit Interactive Dashboard for monitoring threats. The OWASP Top 10 for LLM Applications 2025 comprehensively lists and explains the ten most critical security risks specific to LLMs, such as Prompt Injection, Sensitive Information Disclosure, Supply Chain vulnerabilities, and Excessive Agency.

## 🎥 Demo Video

Watch the LLMGuardian demonstration and walkthrough:

[LLMGuardian Demo](https://youtu.be/vzMJXuoS-ko?si=umzS-6eqKl8mMtY_)

**Author:** [DeWitt Gibson](https://www.linkedin.com/in/dewitt-gibson/)

**Full Documentation and Usage Instructions: [DOCS](docs/README.md)**

## 🚀 Quick Start

### Installation

```bash
# Install from PyPI (when available)
pip install llmguardian

# Or install from source
git clone https://github.com/dewitt4/llmguardian.git
cd llmguardian
pip install -e .
```

### Using Docker

```bash
# Pull the latest image
docker pull ghcr.io/dewitt4/llmguardian:latest

# Run the API server
docker run -p 8000:8000 ghcr.io/dewitt4/llmguardian:latest

# Run the dashboard
docker run -p 8501:8501 ghcr.io/dewitt4/llmguardian:latest streamlit run src/llmguardian/dashboard/app.py
```

See [docker/README.md](docker/README.md) for detailed Docker usage.

### Running the Dashboard

```bash
# Install dashboard dependencies
pip install -e ".[dashboard]"

# Run the Streamlit dashboard
streamlit run src/llmguardian/dashboard/app.py
```

## ✨ Features

### 🛡️ Comprehensive Security Protection

- **Prompt Injection Detection**: Advanced scanning for injection attacks
- **Data Leakage Prevention**: Sensitive data exposure protection
- **Output Validation**: Ensure safe and appropriate model outputs
- **Rate Limiting**: Protect against abuse and DoS attacks
- **Token Validation**: Secure authentication and authorization

### 🔍 Security Scanning & Monitoring

- **Automated Vulnerability Scanning**: Daily security scans with Trivy
- **Dependency Review**: Automated checks for vulnerable dependencies
- **Real-time Threat Detection**: Monitor and detect anomalous behavior
- **Audit Logging**: Comprehensive security event logging
- **Performance Monitoring**: Track system health and performance

### 🐳 Docker & Deployment

- **Pre-built Docker Images**: Available on GitHub Container Registry
- **Multi-architecture Support**: AMD64 and ARM64 builds
- **Automated CI/CD**: GitHub Actions for testing and deployment
- **Security Attestations**: Supply chain security with provenance
- **Health Checks**: Built-in container health monitoring

### 📊 Interactive Dashboard

- **Streamlit Interface**: User-friendly web dashboard
- **Real-time Visualization**: Monitor threats and metrics
- **Configuration Management**: Easy setup and customization
- **Alert Management**: Configure and manage security alerts

## 🏗️ Project Structure

LLMGuardian follows a modular and secure architecture designed to provide comprehensive protection for LLM applications. Below is the detailed project structure with explanations for each component:

## Directory Structure

```
LLMGuardian/
├── .github/                      # GitHub specific configurations
│   ├── workflows/                # GitHub Actions workflows for CI/CD
│   ├── CODEOWNERS               # Repository ownership rules
│   ├── ISSUE_TEMPLATE/          # Issue reporting templates
│   └── PULL_REQUEST_TEMPLATE.md # PR guidelines
│
├── src/                         # Source code
│   └── llmguardian/            # Main package directory
│       ├── cli/                # Command-line interface
│       ├── dashboard/          # Streamlit dashboard
│       ├── core/               # Core functionality
│       ├── scanners/           # Security scanning modules
│       ├── defenders/          # Defense mechanisms
│       ├── monitors/           # Monitoring components
│       ├── api/                # API integration
|       ├── vectors/            # Embeddings protection / supply chain vulnerabilities
|       ├── data/               # Sensive data exposure / data poisoning
|       ├── agency/             # Excessive agency protection
│       └── utils/              # Utility functions
│
├── tests/                      # Test suite
│   ├── unit/                  # Unit tests
│   ├── integration/           # Integration tests
│   └── security/              # Security-specific tests
│
├── docs/                      # Documentation
├── scripts/                   # Utility scripts
├── page/                      # Files for GitHub pages
├── requirements/              # Dependencies
├── docker/                    # Docker configurations
├── config/                    # Various config files
└── app.py                     # Huggingface Space deployment
```

## Component Details

### 🔒 Security Components

1. **Scanners (`src/llmguardian/scanners/`)**
   - Prompt injection detection
   - Data leakage scanning
   - Model security validation
   - Output validation checks

2. **Defenders (`src/llmguardian/defenders/`)**
   - Input sanitization
   - Output filtering
   - Content validation
   - Token validation

3. **Monitors (`src/llmguardian/monitors/`)**
   - Real-time usage tracking
   - Threat detection
   - Anomaly monitoring
   - Performance tracking
   - Audit logging

4. **Vectors (`src/llmguardian/vectors/`)**
   - Embedding weaknesses detection
   - Supply chain vulnerabilities
   - Vector store monitoring
   - Retrieval guard

5. **Data (`src/llmguardian/data/`)**
   - Sensitive information disclosure prevention
   - Protection from data poisoning
   - Data sanitizing
   - Privacy enforcement

6. **Agency (`src/llmguardian/agency/`)**
   - Permission management
   - Scope limitation
   - Action validation
   - Safe execution

### 🛠️ Core Components

7. **CLI (`src/llmguardian/cli/`)**
   - Command-line interface
   - Interactive tools
   - Configuration management

8. **API (`src/llmguardian/api/`)**
   - RESTful endpoints
   - FastAPI integration
   - Security middleware
   - Health check endpoints

9. **Core (`src/llmguardian/core/`)**
   - Configuration management
   - Logging setup
   - Event handling
   - Rate limiting
   - Security utilities

### 🧪 Testing & Quality Assurance

10. **Tests (`tests/`)**
    - Unit tests for individual components
    - Integration tests for system functionality
    - Security-specific test cases
    - Vulnerability testing
    - Automated CI/CD testing

### 📚 Documentation & Support

11. **Documentation (`docs/`)**
    - API documentation
    - Implementation guides
    - Security best practices
    - Usage examples

12. **Docker (`docker/`)**
    - Production-ready Dockerfile
    - Multi-architecture support
    - Container health checks
    - Security optimized

### 🔧 Development Tools

13. **Scripts (`scripts/`)**
    - Setup utilities
    - Development tools
    - Security checking scripts

### 📊 Dashboard

14. **Dashboard (`src/llmguardian/dashboard/`)**
    - Streamlit application
    - Real-time visualization
    - Monitoring and control
    - Alert management

## 🔐 Security Features

### Automated Security Scanning

LLMGuardian includes comprehensive automated security scanning:

- **Daily Vulnerability Scans**: Automated Trivy scans run daily at 2 AM UTC
- **Dependency Review**: All pull requests are automatically checked for vulnerable dependencies
- **Container Scanning**: Docker images are scanned before publication
- **Configuration Validation**: Automated checks for security misconfigurations

### CI/CD Integration

Our GitHub Actions workflows provide:

- **Continuous Integration**: Automated testing on Python 3.8, 3.9, 3.10, and 3.11
- **Code Quality**: Black, Flake8, isort, and mypy checks
- **Security Gates**: Vulnerabilities are caught before merge
- **Automated Deployment**: Docker images published to GitHub Container Registry

### Supply Chain Security

- **SBOM Generation**: Software Bill of Materials for all builds
- **Provenance Attestations**: Cryptographically signed build provenance
- **Multi-architecture Builds**: Support for AMD64 and ARM64

## 🐳 Docker Deployment

### Quick Start with Docker

```bash
# Pull the latest image
docker pull ghcr.io/dewitt4/llmguardian:latest

# Run API server
docker run -p 8000:8000 ghcr.io/dewitt4/llmguardian:latest

# Run with environment variables
docker run -p 8000:8000 \
  -e LOG_LEVEL=DEBUG \
  -e SECURITY_RISK_THRESHOLD=8 \
  ghcr.io/dewitt4/llmguardian:latest
```

### Available Tags

- `latest` - Latest stable release from main branch
- `main` - Latest commit on main branch
- `v*.*.*` - Specific version tags (e.g., v1.0.0)
- `sha-*` - Specific commit SHA tags

### Volume Mounts

```bash
# Persist logs and data
docker run -p 8000:8000 \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/data:/app/data \
  ghcr.io/dewitt4/llmguardian:latest
```

See [docker/README.md](docker/README.md) for complete Docker documentation.

## ☁️ Cloud Deployment

LLMGuardian can be deployed on all major cloud platforms. Below are quick start guides for each provider. For detailed step-by-step instructions, see [PROJECT.md - Cloud Deployment Guides](PROJECT.md#cloud-deployment-guides).

### AWS Deployment

**Option 1: ECS with Fargate (Recommended)**
```bash
# Push to ECR and deploy
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com
aws ecr create-repository --repository-name llmguardian
docker tag llmguardian:latest YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/llmguardian:latest
docker push YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/llmguardian:latest
```

**Other AWS Options:**
- AWS Lambda with Docker containers
- Elastic Beanstalk for PaaS deployment
- EKS for Kubernetes orchestration

### Google Cloud Platform

**Cloud Run (Recommended)**
```bash
# Build and deploy to Cloud Run
gcloud auth configure-docker
docker tag llmguardian:latest gcr.io/YOUR_PROJECT_ID/llmguardian:latest
docker push gcr.io/YOUR_PROJECT_ID/llmguardian:latest

gcloud run deploy llmguardian \
  --image gcr.io/YOUR_PROJECT_ID/llmguardian:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 2Gi \
  --port 8000
```

**Other GCP Options:**
- Google Kubernetes Engine (GKE)
- App Engine for PaaS deployment

### Microsoft Azure

**Azure Container Instances**
```bash
# Create resource group and deploy
az group create --name llmguardian-rg --location eastus
az acr create --resource-group llmguardian-rg --name llmguardianacr --sku Basic
az acr login --name llmguardianacr

docker tag llmguardian:latest llmguardianacr.azurecr.io/llmguardian:latest
docker push llmguardianacr.azurecr.io/llmguardian:latest

az container create \
  --resource-group llmguardian-rg \
  --name llmguardian-container \
  --image llmguardianacr.azurecr.io/llmguardian:latest \
  --cpu 2 --memory 4 --ports 8000
```

**Other Azure Options:**
- Azure App Service (Web App for Containers)
- Azure Kubernetes Service (AKS)
- Azure Functions

### Vercel

**Serverless Deployment**
```bash
# Install Vercel CLI and deploy
npm i -g vercel
vercel login
vercel --prod
```

Create `vercel.json`:
```json
{
  "version": 2,
  "builds": [{"src": "src/llmguardian/api/app.py", "use": "@vercel/python"}],
  "routes": [{"src": "/(.*)", "dest": "src/llmguardian/api/app.py"}]
}
```

### DigitalOcean

**App Platform (Easiest)**
```bash
# Using doctl CLI
doctl auth init
doctl apps create --spec .do/app.yaml
```

**Other DigitalOcean Options:**
- DigitalOcean Kubernetes (DOKS)
- Droplets with Docker

### Platform Comparison

| Platform | Best For | Ease of Setup | Estimated Cost |
|----------|----------|---------------|----------------|
| **GCP Cloud Run** | Startups, Auto-scaling | ⭐⭐⭐⭐⭐ Easy | $30-150/mo |
| **AWS ECS** | Enterprise, Flexibility | ⭐⭐⭐ Medium | $50-200/mo |
| **Azure ACI** | Microsoft Ecosystem | ⭐⭐⭐⭐ Easy | $50-200/mo |
| **Vercel** | API Routes, Serverless | ⭐⭐⭐⭐⭐ Very Easy | $20-100/mo |
| **DigitalOcean** | Simple, Predictable | ⭐⭐⭐⭐ Easy | $24-120/mo |

### Prerequisites for Cloud Deployment

Before deploying to any cloud:

1. **Prepare Environment Variables**: Copy `.env.example` to `.env` and configure
2. **Build Docker Image**: `docker build -t llmguardian:latest -f docker/dockerfile .`
3. **Set Up Cloud CLI**: Install and authenticate with your chosen provider
4. **Configure Secrets**: Use cloud secret managers (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)
5. **Enable HTTPS**: Configure SSL/TLS certificates
6. **Set Up Monitoring**: Enable cloud-native monitoring and logging

For complete deployment guides with step-by-step instructions, configuration examples, and best practices, see **[PROJECT.md - Cloud Deployment Guides](PROJECT.md#cloud-deployment-guides)**.

## ⚙️ Configuration

### Environment Variables

LLMGuardian can be configured using environment variables. Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

Key configuration options:

- `SECURITY_RISK_THRESHOLD`: Risk threshold (1-10)
- `SECURITY_CONFIDENCE_THRESHOLD`: Detection confidence (0.0-1.0)
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `API_SERVER_PORT`: API server port (default: 8000)
- `DASHBOARD_PORT`: Dashboard port (default: 8501)

See `.env.example` for all available options.

## 🚦 GitHub Actions Workflows

### Available Workflows

1. **CI Workflow** (`ci.yml`)
   - Runs on push and PR to main/develop
   - Linting (Black, Flake8, isort, mypy)
   - Testing on multiple Python versions
   - Code coverage reporting

2. **Security Scan** (`security-scan.yml`)
   - Daily automated scans
   - Trivy vulnerability scanning
   - Dependency review on PRs
   - Python Safety checks

3. **Docker Build & Publish** (`docker-publish.yml`)
   - Builds on push to main
   - Multi-architecture builds
   - Security scanning of images
   - Publishes to GitHub Container Registry

4. **File Size Check** (`filesize.yml`)
   - Prevents large files (>10MB)
   - Ensures HuggingFace compatibility

See [.github/workflows/README.md](.github/workflows/README.md) for detailed documentation.

## 📦 Installation Options

### From Source

```bash
git clone https://github.com/dewitt4/llmguardian.git
cd llmguardian
pip install -e .
```

### Development Installation

```bash
pip install -e ".[dev,test]"
```

### Dashboard Installation

```bash
pip install -e ".[dashboard]"
```

## 🧑‍💻 Development

### Running Tests

```bash
# Install test dependencies
pip install -e ".[dev,test]"

# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=term
```

### Code Quality Checks

```bash
# Format code
black src tests

# Sort imports
isort src tests

# Check style
flake8 src tests

# Type checking
mypy src
```

### Local Security Scanning

```bash
# Install Trivy
brew install trivy  # macOS
# or use package manager for Linux

# Scan repository
trivy fs . --severity CRITICAL,HIGH,MEDIUM

# Scan dependencies
pip install safety
safety check
```

## 🌟 Key Files

- `pyproject.toml`: Project metadata and dependencies
- `setup.py`: Package setup configuration
- `requirements/*.txt`: Environment-specific dependencies
- `.env.example`: Environment variable template
- `.dockerignore`: Docker build optimization
- `CONTRIBUTING.md`: Contribution guidelines
- `LICENSE`: Apache 2.0 license terms

## 🎯 Design Principles

The structure follows these key principles:

1. **Modularity**: Each component is self-contained and independently maintainable
2. **Security-First**: Security considerations are built into the architecture
3. **Scalability**: Easy to extend and add new security features
4. **Testability**: Comprehensive test coverage and security validation
5. **Usability**: Clear organization and documentation
6. **Automation**: CI/CD pipelines for testing, security, and deployment

## 🚀 Getting Started with Development

To start working with this structure:

1. **Fork the repository**
   ```bash
   git clone https://github.com/dewitt4/llmguardian.git
   cd llmguardian
   ```

2. **Create and activate a virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -e ".[dev,test]"
   ```

4. **Run the test suite**
   ```bash
   pytest tests/
   ```

5. **Follow the contribution guidelines**
   - See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines

## 🤗 HuggingFace Space

LLMGuardian is available as a HuggingFace Space for easy testing and demonstration:

**[https://huggingface.co/spaces/Safe-Harbor/LLMGuardian](https://huggingface.co/spaces/Safe-Harbor/LLMGuardian)**

### Features

1. **FastAPI Backend**
   - Model scanning endpoints
   - Prompt injection detection
   - Input/output validation
   - Rate limiting middleware
   - Authentication checks

2. **Gradio UI Frontend**
   - Model security testing interface
   - Vulnerability scanning dashboard
   - Real-time attack detection
   - Configuration settings

### Deployment

The HuggingFace Space is automatically synced from the main branch via GitHub Actions. See `.github/workflows/huggingface.yml` for the sync workflow.

## 📊 Status & Monitoring

### GitHub Actions Status

Monitor the health of the project:

- **[CI Pipeline](https://github.com/dewitt4/llmguardian/actions/workflows/ci.yml)**: Continuous integration status
- **[Security Scans](https://github.com/dewitt4/llmguardian/actions/workflows/security-scan.yml)**: Latest security scan results
- **[Docker Builds](https://github.com/dewitt4/llmguardian/actions/workflows/docker-publish.yml)**: Container build status

### Security Advisories

Check the [Security tab](https://github.com/dewitt4/llmguardian/security) for:
- Vulnerability reports
- Dependency alerts
- Security advisories

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Code of conduct
- Development setup
- Pull request process
- Coding standards

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 📝 Citation

If you use LLMGuardian in your research or project, please cite:

```bibtex
@misc{llmguardian2025,
      title={LLMGuardian: Comprehensive LLM AI Model Protection}, 
      author={DeWitt Gibson},
      year={2025},
      url={https://github.com/dewitt4/llmguardian}, 
}
```

## 🔗 Links

- **Documentation**: [docs/README.md](docs/README.md)
- **Docker Hub**: [ghcr.io/dewitt4/llmguardian](https://github.com/dewitt4/LLMGuardian/pkgs/container/llmguardian)
- **HuggingFace Space**: [Safe-Harbor/LLMGuardian](https://huggingface.co/spaces/Safe-Harbor/LLMGuardian)
- **Issues**: [GitHub Issues](https://github.com/dewitt4/LLMGuardian/issues)
- **Pull Requests**: [GitHub PRs](https://github.com/dewitt4/LLMGuardian/pulls)

## Planned Enhancements for 2025-2026

The LLMGuardian project, initially written in 2024, is designed to be a comprehensive security toolset aligned with addressing OWASP vulnerabilities in Large Language Models. The **OWASP Top 10 for LLM Applications 2025** (Version 2025, released November 18, 2024) includes several critical updates, expanded categories, and new entries, specifically reflecting the risks associated with agentic systems, RAG (Retrieval-Augmented Generation), and resource consumption.

Based on the existing structure of LLMGuardian (which includes dedicated components for Prompt Injection Detection, Data Leakage Prevention, Output Validation, Vectors, Data, and Agency protection) and the specific changes introduced in the 2025 list, the following updates and enhancements are necessary to bring the project up to speed.

***

# LLMGuardian 2025 OWASP Top 10 Updates

This list outlines the necessary updates and enhancements to align LLMGuardian with the **OWASP Top 10 for LLM Applications 2025** (Version 2025). Updates in progress.

## Core Security Component Enhancements (Scanners, Defenders, Monitors)

### **LLM01:2025 Prompt Injection**
LLMGuardian currently features Prompt Injection Detection. Updates should focus on newly emerging attack vectors:

*   **Multimodal Injection Detection:** Enhance scanning modules to detect hidden malicious instructions embedded within non-text data types (like images) that accompany benign text inputs, exploiting the complexities of multimodal AI systems.
*   **Obfuscation/Payload Splitting Defense:** Improve defenders' ability to detect and mitigate malicious inputs disguised using payload splitting, multilingual formats, or encoding (e.g., Base64 or emojis).

### **LLM02:2025 Sensitive Information Disclosure**
LLMGuardian includes Sensitive data exposure protection and Data sanitization in the `data/` component.

*   **System Preamble Concealment:** Implement specific checks or guidance within configuration management to verify that system prompts and internal settings are protected and not inadvertently exposed.

### **LLM03:2025 Supply Chain**
LLMGuardian utilizes Dependency Review, SBOM generation, and Provenance Attestations. Updates are required to address model-specific supply chain risks:

*   **Model Provenance and Integrity Vetting:** Implement tooling to perform third-party model integrity checks using signing and file hashes, compensating for the lack of strong model provenance in published models.
*   **LoRA Adapter Vulnerability Scanning:** Introduce specialized scanning for vulnerable LoRA (Low-Rank Adaptation) adapters used during fine-tuning, as these can compromise the integrity of the pre-trained base model.
*   **AI/ML BOM Standards:** Ensure SBOM generation aligns with emerging AI BOMs and ML SBOMs standards, evaluating options starting with OWASP CycloneDX.

### **LLM04:2025 Data and Model Poisoning**
LLMGuardian has features for Protection from data poisoning.

*   **Backdoor/Sleeper Agent Detection:** Enhance model security validation and monitoring components to specifically detect latent backdoors, utilizing adversarial robustness tests during deployment, as subtle triggers can change model behavior later.

### **LLM05:2025 Improper Output Handling**
LLMGuardian includes Output Validation. Improper Output Handling focuses on insufficient validation before outputs are passed downstream.

*   **Context-Aware Output Encoding:** Implement filtering mechanisms within the `defenders/` component to ensure context-aware encoding (e.g., HTML encoding for web content, SQL escaping for database queries) is applied before model output is passed to downstream systems.
*   **Strict Downstream Input Validation:** Ensure all responses coming from the LLM are subject to robust input validation before they are used by backend functions, adhering to OWASP ASVS guidelines.

### **LLM06:2025 Excessive Agency**
LLMGuardian has a dedicated `agency/` component for "Excessive agency protection".

*   **Granular Extension Control:** Enhance permission management within `agency/` to strictly limit the functionality and permissions granted to LLM extensions, enforcing the principle of least privilege on downstream systems.
*   **Human-in-the-Loop Implementation:** Integrate explicit configuration and components to require human approval for high-impact actions before execution, eliminating excessive autonomy.

### **LLM07:2025 System Prompt Leakage**
This is a newly highlighted vulnerability in the 2025 list.

*   **Sensitive Data Removal:** Develop scanning tools to identify and flag embedded sensitive data (API keys, credentials, internal role structures) within system prompts.
*   **Externalized Guardrails Enforcement:** Reinforce the design principle that critical controls (e.g., authorization bounds checks, privilege separation) must be enforced by systems independent of the LLM, rather than delegated through system prompt instructions.

## RAG and Resource Management Updates

### **LLM08:2025 Vector and Embedding Weaknesses**
LLMGuardian has a `vectors/` component dedicated to Embedding weaknesses detection and Retrieval guard. The 2025 guidance strongly focuses on RAG security.

*   **Permission-Aware Vector Stores:** Enhance the Retrieval guard functionality to implement fine-grained access controls and logical partitioning within the vector database to prevent unauthorized access or cross-context information leaks in multi-tenant environments.
*   **RAG Knowledge Base Validation:** Integrate robust data validation pipelines and source authentication for all external knowledge sources used in Retrieval Augmented Generation.

### **LLM09:2025 Misinformation**
This category focuses on addressing hallucinations and overreliance.

*   **Groundedness and Cross-Verification:** Integrate monitoring or evaluation features focused on assessing the "RAG Triad" (context relevance, groundedness, and question/answer relevance) to improve reliability and reduce the risk of misinformation.
*   **Unsafe Code Output Filtering:** Implement filters to vet LLM-generated code suggestions, specifically scanning for and blocking references to insecure or non-existent software packages which could lead to developers downloading malware.

### **LLM10:2025 Unbounded Consumption**
This vulnerability expands beyond DoS to include Denial of Wallet (DoW) and Model Extraction. LLMGuardian already provides Rate Limiting.

*   **Model Extraction Defenses:** Implement features to limit the exposure of sensitive model information (such as `logit_bias` and `logprobs`) in API responses to prevent functional model replication or model extraction attacks.
*   **Watermarking Implementation:** Explore and integrate watermarking frameworks to embed and detect unauthorized use of LLM outputs, serving as a deterrent against model theft.
*   **Enhanced Resource Monitoring:** Expand monitoring to detect patterns indicative of DoW attacks, setting triggers based on consumption limits (costs) rather than just request volume.

## 🙏 Acknowledgments

Built with alignment to [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/)

---

**Built with ❤️ for secure AI development**
