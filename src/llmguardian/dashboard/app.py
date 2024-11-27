# src/llmguardian/dashboard/app.py

import streamlit as st
import plotly.express as px
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any
from ..core.config import Config
from ..data.privacy_guard import PrivacyGuard
from ..monitors.usage_monitor import UsageMonitor
from ..vectors.vector_scanner import VectorScanner

class LLMGuardianDashboard:
    def __init__(self):
        self.config = Config()
        self.privacy_guard = PrivacyGuard()
        self.usage_monitor = UsageMonitor()
        self.vector_scanner = VectorScanner()

    def run(self):
        st.set_page_config(page_title="LLMGuardian Dashboard", layout="wide")
        st.title("LLMGuardian Security Dashboard")

        # Sidebar navigation
        page = st.sidebar.selectbox(
            "Navigation",
            ["Overview", "Privacy Monitor", "Vector Security", "Usage Stats", "Settings"]
        )

        if page == "Overview":
            self._render_overview()
        elif page == "Privacy Monitor":
            self._render_privacy_monitor()
        elif page == "Vector Security":
            self._render_vector_security()
        elif page == "Usage Stats":
            self._render_usage_stats()
        elif page == "Settings":
            self._render_settings()

    def _render_overview(self):
        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(
                "Privacy Violations",
                self._get_privacy_violations_count(),
                self._get_privacy_violations_delta()
            )

        with col2:
            st.metric(
                "Security Score",
                f"{self._calculate_security_score()}%",
                self._get_security_score_delta()
            )

        with col3:
            st.metric(
                "Active Monitors",
                self._get_active_monitors_count()
            )

        # Security alerts
        st.subheader("Recent Security Alerts")
        alerts = self._get_recent_alerts()
        for alert in alerts:
            st.error(alert)

        # Usage trends
        st.subheader("Usage Trends")
        fig = self._create_usage_trend_chart()
        st.plotly_chart(fig, use_container_width=True)

    def _render_privacy_monitor(self):
        st.subheader("Privacy Monitoring")
        
        # Privacy violations by category
        violations_df = self._get_privacy_violations_data()
        fig = px.pie(violations_df, values='count', names='category', 
                    title='Privacy Violations by Category')
        st.plotly_chart(fig)

        # Privacy rules status
        st.subheader("Privacy Rules Status")
        rules_df = self._get_privacy_rules_status()
        st.dataframe(rules_df)

        # Real-time monitoring
        st.subheader("Real-time Privacy Monitoring")
        if st.button("Check Privacy Now"):
            self._run_privacy_check()

    def _render_vector_security(self):
        st.subheader("Vector Security Analysis")

        # Vector anomalies
        anomalies_df = self._get_vector_anomalies()
        st.dataframe(anomalies_df)

        # Vector clustering visualization
        fig = self._create_vector_cluster_chart()
        st.plotly_chart(fig)

        # Scan vectors
        st.subheader("Vector Scanner")
        if st.button("Scan Vectors"):
            self._run_vector_scan()

    def _render_usage_stats(self):
        st.subheader("System Usage Statistics")
        
        # Resource usage
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("CPU Usage", f"{self._get_cpu_usage()}%")
        with col2:
            st.metric("Memory Usage", f"{self._get_memory_usage()}%")
        with col3:
            st.metric("Request Rate", f"{self._get_request_rate()}/min")

        # Usage history
        st.line_chart(self._get_usage_history())

    def _render_settings(self):
        st.subheader("LLMGuardian Settings")

        # Config sections
        with st.expander("Security Settings"):
            self._render_security_settings()

        with st.expander("Privacy Settings"):
            self._render_privacy_settings()

        with st.expander("Monitoring Settings"):
            self._render_monitoring_settings()

    def _calculate_security_score(self) -> float:
        # Implementation of security score calculation
        return 85.5

    def _get_privacy_violations_count(self) -> int:
        # Get privacy violations count
        return len(self.privacy_guard.check_history)

    def _get_recent_alerts(self) -> List[str]:
        # Get recent security alerts
        return ["Critical: High risk privacy violation detected", 
                "Warning: Unusual vector pattern detected"]

    def _create_usage_trend_chart(self):
        # Create usage trend visualization
        df = pd.DataFrame({
            'timestamp': pd.date_range(start='2024-01-01', periods=10),
            'value': [10, 15, 13, 17, 20, 25, 30, 35, 45, 50]
        })
        return px.line(df, x='timestamp', y='value', title='Usage Trend')

    def _get_vector_anomalies(self) -> pd.DataFrame:
        # Get vector anomalies data
        return pd.DataFrame({
            'timestamp': ['2024-01-01', '2024-01-02'],
            'type': ['outlier', 'cluster'],
            'severity': ['high', 'medium']
        })

    def _run_privacy_check(self):
        st.info("Running privacy check...")
        # Implement privacy check logic
        st.success("Privacy check completed")

    def _run_vector_scan(self):
        st.info("Scanning vectors...")
        # Implement vector scan logic
        st.success("Vector scan completed")

if __name__ == "__main__":
    dashboard = LLMGuardianDashboard()
    dashboard.run()