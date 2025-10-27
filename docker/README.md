# Docker Configuration

This directory contains Docker configuration for LLMGuardian.

## Quick Start

### Using Pre-built Images from GitHub Container Registry

Pull and run the latest image:

```bash
docker pull ghcr.io/dewitt4/llmguardian:latest
docker run -p 8000:8000 -p 8501:8501 ghcr.io/dewitt4/llmguardian:latest
```

### Building Locally

Build the Docker image:

```bash
docker build -f docker/dockerfile -t llmguardian:local .
```

Run the container:

```bash
docker run -p 8000:8000 -p 8501:8501 llmguardian:local
```

## Available Tags

- `latest` - Latest stable release from main branch
- `v*.*.*` - Specific version tags (e.g., v1.0.0)
- `main` - Latest commit on main branch
- `develop` - Latest commit on develop branch

## Environment Variables

Configure the container using environment variables:

```bash
docker run -p 8000:8000 \
  -e SECURITY_RISK_THRESHOLD=8 \
  -e LOG_LEVEL=DEBUG \
  -e API_SERVER_PORT=8000 \
  ghcr.io/dewitt4/llmguardian:latest
```

See `.env.example` in the root directory for all available environment variables.

## Exposed Ports

- `8000` - API Server
- `8501` - Dashboard (Streamlit)

## Volume Mounts

Mount volumes for persistent data:

```bash
docker run -p 8000:8000 \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/data:/app/data \
  ghcr.io/dewitt4/llmguardian:latest
```

## Docker Compose (Example)

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  llmguardian-api:
    image: ghcr.io/dewitt4/llmguardian:latest
    ports:
      - "8000:8000"
    environment:
      - LOG_LEVEL=INFO
      - SECURITY_RISK_THRESHOLD=7
    volumes:
      - ./logs:/app/logs
      - ./data:/app/data
    restart: unless-stopped

  llmguardian-dashboard:
    image: ghcr.io/dewitt4/llmguardian:latest
    command: ["streamlit", "run", "src/llmguardian/dashboard/app.py"]
    ports:
      - "8501:8501"
    environment:
      - DASHBOARD_PORT=8501
      - DASHBOARD_HOST=0.0.0.0
    depends_on:
      - llmguardian-api
    restart: unless-stopped
```

Run with:

```bash
docker-compose up -d
```

## Health Check

The container includes a health check endpoint:

```bash
curl http://localhost:8000/health
```

## Security Scanning

All published images are automatically scanned with Trivy for vulnerabilities. Check the [Security tab](https://github.com/dewitt4/LLMGuardian/security) for scan results.

## Multi-Architecture Support

Images are built for both AMD64 and ARM64 architectures:

```bash
# Automatically pulls the correct architecture
docker pull ghcr.io/dewitt4/llmguardian:latest
```

## Troubleshooting

### Permission Issues

If you encounter permission issues with volume mounts:

```bash
docker run --user $(id -u):$(id -g) \
  -v $(pwd)/logs:/app/logs \
  ghcr.io/dewitt4/llmguardian:latest
```

### View Logs

```bash
docker logs <container-id>
```

### Interactive Shell

```bash
docker run -it --entrypoint /bin/bash ghcr.io/dewitt4/llmguardian:latest
```

## CI/CD Integration

Images are automatically built and published via GitHub Actions:

- **On push to main**: Builds and publishes `latest` tag
- **On version tags**: Builds and publishes version-specific tags
- **On pull requests**: Builds image but doesn't publish
- **Daily security scans**: Automated Trivy scans

See `.github/workflows/docker-publish.yml` for workflow details.
