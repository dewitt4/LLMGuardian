"""
LLMGuardian Dashboard Demo Script
==================================

This script launches the LLMGuardian security dashboard in demo mode
with pre-populated data for testing and demonstration purposes.

Usage:
    python demo_dashboard.py

Requirements:
    - streamlit
    - plotly
    - pandas
    - numpy

The dashboard will be available at http://localhost:8501
"""

import subprocess
import sys
import os
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    required = ['streamlit', 'plotly', 'pandas', 'numpy']
    missing = []
    
    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    return missing

def install_dependencies(packages):
    """Install missing dependencies"""
    print(f"Installing missing dependencies: {', '.join(packages)}")
    subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + packages)

def main():
    print("=" * 60)
    print("LLMGuardian Dashboard Demo")
    print("=" * 60)
    print()
    
    # Check dependencies
    missing = check_dependencies()
    if missing:
        print(f"⚠️  Missing dependencies detected: {', '.join(missing)}")
        response = input("Would you like to install them now? (y/n): ")
        if response.lower() == 'y':
            install_dependencies(missing)
            print("✅ Dependencies installed successfully!")
        else:
            print("❌ Cannot run dashboard without required dependencies.")
            return
    
    print("✅ All dependencies are installed")
    print()
    
    # Get the dashboard script path
    script_dir = Path(__file__).parent
    dashboard_path = script_dir / "src" / "llmguardian" / "dashboard" / "app.py"
    
    if not dashboard_path.exists():
        print(f"❌ Dashboard script not found at: {dashboard_path}")
        return
    
    print("🚀 Starting LLMGuardian Dashboard in demo mode...")
    print()
    print("📊 Dashboard Features:")
    print("   • Real-time security monitoring")
    print("   • Threat detection and analysis")
    print("   • Privacy violation tracking")
    print("   • Usage analytics and metrics")
    print("   • Interactive security scanner")
    print()
    print("🌐 Dashboard will open at: http://localhost:8501")
    print("⏹️  Press Ctrl+C to stop the dashboard")
    print()
    print("=" * 60)
    print()
    
    # Run streamlit with the dashboard
    try:
        subprocess.run([
            sys.executable, '-m', 'streamlit', 'run',
            str(dashboard_path),
            '--server.port=8501',
            '--server.address=localhost',
            '--',
            '--demo'
        ])
    except KeyboardInterrupt:
        print("\n\n👋 Dashboard stopped. Thank you for using LLMGuardian!")
    except Exception as e:
        print(f"\n❌ Error running dashboard: {e}")

if __name__ == "__main__":
    main()
