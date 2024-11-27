# LLMGuardian API Documentation

## Base URL
`https://api.llmguardian.com/v1` # replace llmguardian.com with your domain

## Authentication
Bearer token required in Authorization header:
```
Authorization: Bearer <your_token>
```

## Endpoints

### Security Scan
`POST /scan`

Scans content for security violations.

**Request:**
```json
{
  "content": "string",
  "context": {
    "source": "string",
    "user_id": "string"
  },
  "security_level": "medium"
}
```

**Response:**
```json
{
  "is_safe": true,
  "risk_level": "low",
  "violations": [
    {
      "type": "string",
      "description": "string",
      "location": "string"
    }
  ],
  "recommendations": [
    "string"
  ],
  "metadata": {
    "timestamp": "2024-01-01T00:00:00Z"
  }
}
```

### Privacy Check
`POST /privacy/check`

Checks content for privacy violations.

**Request:**
```json
{
  "content": "string",
  "privacy_level": "confidential",
  "context": {
    "department": "string",
    "data_type": "string"
  }
}
```

**Response:**
```json
{
  "compliant": true,
  "violations": [
    {
      "category": "PII",
      "details": "string",
      "severity": "high"
    }
  ],
  "modified_content": "string",
  "metadata": {
    "timestamp": "2024-01-01T00:00:00Z"
  }
}
```

### Vector Scan
`POST /vectors/scan`

Scans vector embeddings for security issues.

**Request:**
```json
{
  "vectors": [
    [0.1, 0.2, 0.3]
  ],
  "metadata": {
    "model": "string",
    "source": "string"
  }
}
```

**Response:**
```json
{
  "is_safe": true,
  "vulnerabilities": [
    {
      "type": "poisoning",
      "severity": "high",
      "affected_indices": [1, 2, 3]
    }
  ],
  "recommendations": [
    "string"
  ]
}
```

## Error Responses
```json
{
  "detail": "Error message",
  "error_code": "ERROR_CODE",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Rate Limiting
- 100 requests per minute per API key
- 429 Too Many Requests response when exceeded

## SDKs
```python
from llmguardian import Client

client = Client("<api_key>")
result = client.scan_content("text to scan")
```

## Examples
```python
# Security scan
response = requests.post(
    "https://api.llmguardian.com/v1/scan",  # replace llmguardian.com with your domain
    headers={"Authorization": f"Bearer {token}"},
    json={
        "content": "sensitive text",
        "security_level": "high"
    }
)

# Privacy check with context
response = requests.post(
    "https://api.llmguardian.com/v1/privacy/check",
    headers={"Authorization": f"Bearer {token}"},
    json={
        "content": "text with PII",
        "privacy_level": "restricted",
        "context": {"department": "HR"}
    }
)
```

## Webhook Events
```json
{
  "event": "security_violation",
  "data": {
    "violation_type": "string",
    "severity": "high",
    "timestamp": "2024-01-01T00:00:00Z"
  }
}
```

## API Status
Check status at: https://status.llmguardian.com # replace llmguardian.com with your domain

Rate limits and API metrics available in dashboard.
