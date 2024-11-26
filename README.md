# LLMGuardian
Comprehensive LLM protection toolset aligned to addressing OWASP vulnerabilities

Author: DeWitt Gibson https://www.linkedin.com/in/dewitt-gibson/

**Full Documentaion and Usage Instructions: [DOCS](docs/README.md)**

**Please see the Projects and Issues tab above for completion roadmap**

# Project Structure

LLMGuardian follows a modular and secure architecture designed to provide comprehensive protection for LLM applications. Below is the detailed project structure with explanations for each component:

## Directory Structure

```
LLMGuardian/
├── .github/                      # GitHub specific configurations
│   ├── workflows/                # GitHub Actions workflows
│   ├── CODEOWNERS               # Repository ownership rules
│   ├── ISSUE_TEMPLATE/          # Issue reporting templates
│   └── PULL_REQUEST_TEMPLATE.md # PR guidelines
│
├── src/                         # Source code
│   └── llmguardian/            # Main package directory
│       ├── cli/                # Command-line interface
│       ├── core/               # Core functionality
│       ├── scanners/           # Security scanning modules
│       ├── defenders/          # Defense mechanisms
│       ├── monitors/           # Monitoring components
│       ├── api/                # API integration
|       ├── vectors/            # Storage Validation
│       └── utils/              # Utility functions
│
├── tests/                      # Test suite
│   ├── unit/                  # Unit tests
│   ├── integration/           # Integration tests
│   └── security/              # Security-specific tests
│
├── docs/                      # Documentation
├── scripts/                   # Utility scripts
├── requirements/              # Dependencies
├── docker/                    # Docker configurations
└── [Configuration Files]      # Various config files
```

## Component Details

### Security Components

1. **Scanners (`src/llmguardian/scanners/`)**
   - Prompt injection detection
   - Data leakage scanning
   - Model security validation
   - Output validation checks

2. **Defenders (`src/llmguardian/defenders/`)**
   - Input sanitization
   - Output filtering
   - Rate limiting
   - Token validation

4. **Monitors (`src/llmguardian/monitors/`)**
   - Real-time usage tracking
   - Threat detection
   - Anomaly monitoring

5. **Vectors ('src/llmguardian/vectors/')**
   - 
   - Protection for RAG documents
   - Montior vector stores

6. **Data ('src/llmguardian/data/')**
   - Real-time usage tracking
   - Threat detection
   - Anomaly monitoring

7. **Agency ('src/llmguardian/agency/')**
   - Real-time usage tracking
   - Threat detection
   - Anomaly monitoring

### Core Components

8. **CLI (`src/llmguardian/cli/`)**
   - Command-line interface
   - Interactive tools
   - Configuration management

9. **API (`src/llmguardian/api/`)**
   - RESTful endpoints
   - Middleware
   - Integration interfaces

10. **Core (`src/llmguardian/core/`)**
   - Configuration management
   - Logging setup
   - Core functionality
  
### Testing & Quality Assurance

11. **Tests (`tests/`)**
   - Unit tests for individual components
   - Integration tests for system functionality
   - Security-specific test cases
   - Vulnerability testing

### Documentation & Support

12. **Documentation (`docs/`)**
   - API documentation
   - Implementation guides
   - Security best practices
   - Usage examples

13. **Docker (`docker/`)**
   - Containerization support
   - Development environment
   - Production deployment

### Development Tools

14. **Scripts (`scripts/`)**
    - Setup utilities
    - Development tools
    - Security checking scripts

## Key Files

- `pyproject.toml`: Project metadata and dependencies
- `setup.py`: Package setup configuration
- `requirements/*.txt`: Environment-specific dependencies
- `.pre-commit-config.yaml`: Code quality hooks
- `CONTRIBUTING.md`: Contribution guidelines
- `LICENSE`: MIT license terms

## Design Principles

The structure follows these key principles:

1. **Modularity**: Each component is self-contained and independently maintainable
2. **Security-First**: Security considerations are built into the architecture
3. **Scalability**: Easy to extend and add new security features
4. **Testability**: Comprehensive test coverage and security validation
5. **Usability**: Clear organization and documentation

## Getting Started with Development

To start working with this structure:

1. Fork the repository
2. Create and activate a virtual environment
3. Install dependencies from the appropriate requirements file
4. Run the test suite to ensure everything is working
5. Follow the contribution guidelines for making changes
