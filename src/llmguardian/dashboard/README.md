# LLMGuardian Dashboard

A web-based monitoring and control interface for LLMGuardian security features, built with Streamlit.

## Features

- Real-time security monitoring
- Privacy violation tracking
- Vector security analysis
- System usage statistics
- Configuration management

## Installation

```bash
pip install -r requirements/dashboard.txt
```

## Quick Start

```bash
python -m llmguardian.dashboard.app
```

Visit `http://localhost:8501` in your browser.

## Components

### Overview Page
- Security metrics
- Recent alerts
- Usage trends
- System health status

### Privacy Monitor
- Real-time privacy violations
- Category-based analysis
- Rule management
- Compliance tracking

### Vector Security
- Anomaly detection
- Cluster visualization
- Vector scanning
- Threat analysis

### Usage Statistics
- Resource monitoring
- Request tracking
- Performance metrics
- Historical data

### Settings
- Security configuration
- Privacy rules
- Monitoring parameters
- System preferences

## Configuration

```python
# config/dashboard_config.yaml
server:
  port: 8501
  host: "0.0.0.0"

monitoring:
  refresh_rate: 60  # seconds
  alert_threshold: 0.8
  retention_period: 7  # days
```

## Docker Support

```bash
docker build -t llmguardian-dashboard .
docker run -p 8501:8501 llmguardian-dashboard
```

## Security

- Authentication required
- HTTPS support
- Role-based access
- Audit logging

## API Integration

```python
from llmguardian.dashboard import LLMGuardianDashboard

dashboard = LLMGuardianDashboard()
dashboard.run()
```