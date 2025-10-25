# LLMGuardian Dashboard

Interactive web dashboard for comprehensive LLM security monitoring and management.

## 🎯 Features

### 📊 Overview Dashboard
- **Real-time Security Metrics**: Monitor security score, privacy violations, active monitors, and blocked threats
- **Security Trends**: 30-day visualization of security events and trends
- **Threat Distribution**: Interactive charts showing threat categories
- **Recent Alerts**: Live security alert feed with severity indicators
- **System Status**: Uptime monitoring and response time tracking

### 🔒 Privacy Monitor
- **PII Detection**: Automatic detection of personally identifiable information
- **Data Leak Prevention**: Real-time monitoring for data exfiltration attempts
- **Privacy Violations Tracking**: Categorized breakdown of privacy issues
- **Compliance Score**: Real-time GDPR/CCPA compliance metrics
- **Interactive Privacy Scanner**: Test inputs for privacy violations

### ⚠️ Threat Detection
- **Multi-Category Threat Analysis**: Prompt injection, data leakage, DoS, poisoning, and more
- **Threat Timeline**: Historical view of detected threats
- **Active Threat Dashboard**: Real-time monitoring of active security threats
- **Severity-Based Filtering**: View threats by criticality level
- **Threat Statistics**: Comprehensive metrics and analytics

### 📈 Usage Analytics
- **System Resource Monitoring**: CPU, memory, and disk usage tracking
- **Request Rate Analysis**: Monitor API request patterns
- **Response Time Distribution**: Performance metrics and histograms
- **Performance Metrics**: P95, P99 latency tracking
- **Historical Trends**: 30-day usage history

### 🔍 Security Scanner
- **Interactive Prompt Testing**: Scan inputs for security vulnerabilities
- **Multi-Mode Scanning**: Quick, standard, and deep scan options
- **Adjustable Sensitivity**: Fine-tune detection thresholds
- **Detailed Findings**: Comprehensive vulnerability reports
- **Scan History**: Track all previous security scans

### ⚙️ Settings & Configuration
- **Security Settings**: Configure threat detection and blocking rules
- **Privacy Settings**: Customize PII detection and data protection
- **Monitoring Settings**: Adjust refresh rates and retention periods
- **Notification Settings**: Email and Slack alert configuration
- **System Information**: Version info and update checking

## 🚀 Quick Start

### Option 1: Demo Mode (Recommended for Testing)

Run the dashboard with demo data:

```bash
# From project root
python demo_dashboard.py
```

Or directly with streamlit:

```bash
streamlit run src/llmguardian/dashboard/app.py -- --demo
```

### Option 2: Live Mode (Production)

Run with real LLMGuardian integration:

```bash
streamlit run src/llmguardian/dashboard/app.py
```

The dashboard will be available at: http://localhost:8501

## 📋 Requirements

### Core Dependencies
```
streamlit>=1.28.0
plotly>=5.17.0
pandas>=2.0.0
numpy>=1.24.0
```

### Optional Dependencies (for live mode)
```
psutil>=5.9.0  # For system resource monitoring
```

## 🎨 Dashboard Pages

### 1. Overview
The main landing page provides a comprehensive at-a-glance view of your LLM security posture:
- Key performance indicators (KPIs)
- Security trends over time
- Recent security alerts
- System health status

### 2. Privacy Monitor
Deep dive into privacy protection:
- Real-time PII detection
- Privacy violation categorization
- Compliance scoring
- Interactive privacy testing tool

### 3. Threat Detection
Comprehensive threat analysis:
- Threat distribution by category
- Timeline of detected threats
- Active threat monitoring
- Detailed threat information

### 4. Usage Analytics
Performance and resource monitoring:
- System resource utilization
- API request patterns
- Response time analysis
- Historical performance data

### 5. Security Scanner
Interactive security testing tool:
- Prompt injection detection
- Jailbreak pattern recognition
- Data exfiltration checks
- Customizable scan parameters

### 6. Settings
Configuration and system information:
- Security rule configuration
- Privacy settings management
- Monitoring parameters
- Alert notifications
- About and version info

## 🎮 Demo Mode Features

When running in demo mode, the dashboard includes:

- **Pre-populated Data**: Realistic security metrics and trends
- **Simulated Threats**: Sample threat detections across all categories
- **Interactive Scanning**: Test the security scanner with sample inputs
- **Sample Alerts**: Demonstration of the alert system
- **Full Functionality**: All dashboard features are accessible

## 🔧 Configuration

The dashboard can be configured via `config/dashboard_config.yaml`:

```yaml
server:
  port: 8501
  host: "0.0.0.0"

monitoring:
  refresh_rate: 60  # seconds
  alert_threshold: 0.8
  retention_period: 7  # days
```

## 📊 Metrics and KPIs

### Security Score
Calculated based on:
- Number of blocked threats
- Privacy violation rate
- System compliance level
- Active security monitors
- Recent incident history

### Threat Categories
- **Prompt Injection**: Attempts to manipulate model behavior
- **Data Leakage**: Unauthorized data exposure risks
- **Denial of Service**: Resource exhaustion attacks
- **Model Poisoning**: Training data manipulation
- **Unauthorized Access**: Authentication bypass attempts

### Privacy Metrics
- **PII Detections**: Count of personal information exposures
- **Data Leaks Prevented**: Successfully blocked data exfiltration
- **Compliance Score**: Percentage adherence to privacy regulations

## 🎯 Use Cases

### 1. Development & Testing
- Test prompts for security vulnerabilities
- Validate privacy controls
- Monitor application behavior

### 2. Production Monitoring
- Real-time threat detection
- Compliance monitoring
- Performance tracking

### 3. Security Auditing
- Historical threat analysis
- Compliance reporting
- Incident investigation

### 4. Team Collaboration
- Shared security visibility
- Alert management
- Performance benchmarking

## 🔐 Security Features

- **Real-time Scanning**: Immediate threat detection
- **Pattern Recognition**: ML-powered anomaly detection
- **Privacy Protection**: Automatic PII redaction
- **Audit Logging**: Comprehensive event tracking
- **Alert System**: Multi-channel notifications

## 📱 Browser Compatibility

The dashboard works best with:
- Chrome/Edge (recommended)
- Firefox
- Safari

## 🐛 Troubleshooting

### Dashboard won't start
```bash
# Check if streamlit is installed
python -m streamlit --version

# Install if missing
pip install streamlit plotly pandas numpy
```

### Import errors in live mode
```bash
# Install LLMGuardian package
pip install -e .
```

### Port already in use
```bash
# Use a different port
streamlit run src/llmguardian/dashboard/app.py --server.port=8502
```

## 🤝 Contributing

Contributions to improve the dashboard are welcome! Areas for enhancement:
- Additional visualization types
- New security metrics
- Enhanced threat detection
- UI/UX improvements

## 📄 License

Apache-2.0 License - See LICENSE file for details

## 🔗 Related Documentation

- [Main README](../../../README.md)
- [API Documentation](../api/README.md)
- [Security Scanner](../scanners/README.md)
- [Privacy Guard](../data/README.md)

## 💡 Tips

1. **Start in Demo Mode**: Test all features before connecting to production
2. **Monitor Regularly**: Set up automated monitoring with alerts
3. **Customize Thresholds**: Adjust sensitivity based on your use case
4. **Review Scan History**: Learn from past detections
5. **Export Data**: Use the data tables for reporting and analysis

## 📧 Support

For issues or questions:
- GitHub Issues: [Report a bug](https://github.com/Safe-Harbor-Cybersecurity/LLMGuardian/issues)
- Documentation: [Full Docs](../../../docs/README.md)

---

**Version**: 1.4.0  
**Last Updated**: October 2025
