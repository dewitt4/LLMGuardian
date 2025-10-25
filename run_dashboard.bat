@echo off
REM LLMGuardian Dashboard Launcher for Windows
REM Run this file to start the dashboard

echo ========================================
echo LLMGuardian Security Dashboard
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

echo Checking dependencies...
pip show streamlit >nul 2>&1
if errorlevel 1 (
    echo Installing required dependencies...
    pip install streamlit plotly pandas numpy psutil
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
    echo Dependencies installed successfully!
    echo.
)

echo Starting LLMGuardian Dashboard...
echo Dashboard will open at http://localhost:8501
echo Press Ctrl+C to stop
echo.

REM Run the dashboard in demo mode
python demo_dashboard.py

pause
