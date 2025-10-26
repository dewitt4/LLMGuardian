# LLMGuardian Requirements Files

This directory contains various requirements files for different use cases.

## Files

### For Development & Production

- **`requirements-full.txt`** - Complete requirements for local development
  - Use this for development: `pip install -r requirements-full.txt`
  - Includes all dependencies via `-r requirements/base.txt`

- **`requirements/base.txt`** - Core dependencies
- **`requirements/dev.txt`** - Development tools
- **`requirements/test.txt`** - Testing dependencies
- **`requirements/dashboard.txt`** - Dashboard dependencies
- **`requirements/prod.txt`** - Production dependencies

### For Deployment

- **`requirements.txt`** (root) - Minimal requirements for HuggingFace Space
  - Nearly empty - HuggingFace provides Gradio automatically
  - Used only for the demo Space deployment

- **`requirements-space.txt`** - Alternative minimal requirements
- **`requirements-hf.txt`** - Another lightweight option

## Installation Guide

### Local Development (Full Features)

```bash
# Clone the repository
git clone https://github.com/dewitt4/LLMGuardian.git
cd LLMGuardian

# Install with all dependencies
pip install -r requirements-full.txt

# Or install as editable package
pip install -e ".[dev,test]"
```

### HuggingFace Space (Demo)

The `requirements.txt` in the root is intentionally minimal for the HuggingFace Space demo, which only needs Gradio (provided by HuggingFace).

### Docker Deployment

The Dockerfile uses `requirements-full.txt` for complete functionality.

## Why Multiple Files?

1. **Separation of Concerns**: Different environments need different dependencies
2. **HuggingFace Compatibility**: HuggingFace Spaces can't handle `-r` references to subdirectories
3. **Minimal Demo**: The HuggingFace Space is a lightweight demo, not full installation
4. **Development Flexibility**: Developers can install only what they need

## Quick Reference

| Use Case | Command |
|----------|---------|
| Full local development | `pip install -r requirements-full.txt` |
| Package installation | `pip install -e .` |
| Development with extras | `pip install -e ".[dev,test]"` |
| Dashboard only | `pip install -e ".[dashboard]"` |
| HuggingFace Space | Automatic (uses `requirements.txt`) |
| Docker | Handled by Dockerfile |
