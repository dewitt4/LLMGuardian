"""
Test script to verify the LLMGuardian Dashboard installation
"""

import sys
import subprocess

def test_dependencies():
    """Test if all required dependencies are available"""
    print("=" * 60)
    print("Testing Dashboard Dependencies")
    print("=" * 60)
    
    required_packages = {
        'streamlit': '1.28.0',
        'plotly': '5.17.0',
        'pandas': '2.0.0',
        'numpy': '1.24.0',
    }
    
    optional_packages = {
        'psutil': '5.9.0',
    }
    
    all_ok = True
    
    print("\nRequired Packages:")
    for package, min_version in required_packages.items():
        try:
            mod = __import__(package)
            version = getattr(mod, '__version__', 'unknown')
            print(f"  ✓ {package:15} {version}")
        except ImportError:
            print(f"  ✗ {package:15} NOT INSTALLED (need >={min_version})")
            all_ok = False
    
    print("\nOptional Packages:")
    for package, min_version in optional_packages.items():
        try:
            mod = __import__(package)
            version = getattr(mod, '__version__', 'unknown')
            print(f"  ✓ {package:15} {version}")
        except ImportError:
            print(f"  ⚠ {package:15} NOT INSTALLED (optional, need >={min_version})")
    
    return all_ok


def test_dashboard_import():
    """Test if dashboard can be imported"""
    print("\n" + "=" * 60)
    print("Testing Dashboard Import")
    print("=" * 60)
    
    try:
        sys.path.insert(0, 'src')
        from llmguardian.dashboard.app import LLMGuardianDashboard
        print("  ✓ Dashboard module imported successfully")
        
        # Try to create instance in demo mode
        dashboard = LLMGuardianDashboard(demo_mode=True)
        print("  ✓ Dashboard instance created in demo mode")
        
        return True
    except Exception as e:
        print(f"  ✗ Error importing dashboard: {e}")
        return False


def test_demo_launcher():
    """Test if demo launcher exists and is valid"""
    print("\n" + "=" * 60)
    print("Testing Demo Launcher")
    print("=" * 60)
    
    import os
    
    files_to_check = [
        'demo_dashboard.py',
        'run_dashboard.bat',
        'run_dashboard.ps1',
        'examples_dashboard.py',
    ]
    
    all_ok = True
    for filename in files_to_check:
        if os.path.exists(filename):
            print(f"  ✓ {filename:25} exists")
        else:
            print(f"  ✗ {filename:25} NOT FOUND")
            all_ok = False
    
    return all_ok


def test_documentation():
    """Test if documentation files exist"""
    print("\n" + "=" * 60)
    print("Testing Documentation")
    print("=" * 60)
    
    import os
    
    docs = [
        'DASHBOARD_QUICKSTART.md',
        'DASHBOARD_BUILD_SUMMARY.md',
        'src/llmguardian/dashboard/README_FULL.md',
        'requirements/dashboard.txt',
    ]
    
    all_ok = True
    for doc in docs:
        if os.path.exists(doc):
            print(f"  ✓ {doc:45} exists")
        else:
            print(f"  ✗ {doc:45} NOT FOUND")
            all_ok = False
    
    return all_ok


def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("LLMGuardian Dashboard Installation Test")
    print("=" * 60)
    
    results = {
        'Dependencies': test_dependencies(),
        'Dashboard Import': test_dashboard_import(),
        'Demo Launcher': test_demo_launcher(),
        'Documentation': test_documentation(),
    }
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {test_name:20} {status}")
    
    all_passed = all(results.values())
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ All tests passed! Dashboard is ready to use.")
        print("\nTo start the dashboard, run:")
        print("  python demo_dashboard.py")
    else:
        print("⚠ Some tests failed. Please install missing dependencies:")
        print("  pip install -r requirements/dashboard.txt")
    print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
