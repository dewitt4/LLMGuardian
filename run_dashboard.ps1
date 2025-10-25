# LLMGuardian Dashboard Launcher (PowerShell)
# Run this script to start the dashboard: .\run_dashboard.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "LLMGuardian Security Dashboard" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is installed
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ ERROR: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.8 or higher from https://www.python.org" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "Checking dependencies..." -ForegroundColor Yellow

# Check for required packages
$requiredPackages = @("streamlit", "plotly", "pandas", "numpy")
$missingPackages = @()

foreach ($package in $requiredPackages) {
    try {
        pip show $package 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $missingPackages += $package
        }
    } catch {
        $missingPackages += $package
    }
}

if ($missingPackages.Count -gt 0) {
    Write-Host "Installing missing dependencies: $($missingPackages -join ', ')" -ForegroundColor Yellow
    Write-Host ""
    
    pip install $missingPackages
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "✗ ERROR: Failed to install dependencies" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    Write-Host ""
    Write-Host "✓ Dependencies installed successfully!" -ForegroundColor Green
} else {
    Write-Host "✓ All dependencies are installed" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Starting LLMGuardian Dashboard..." -ForegroundColor Green
Write-Host ""
Write-Host "Dashboard Features:" -ForegroundColor Yellow
Write-Host "  • Real-time security monitoring" -ForegroundColor White
Write-Host "  • Threat detection and analysis" -ForegroundColor White
Write-Host "  • Privacy violation tracking" -ForegroundColor White
Write-Host "  • Usage analytics" -ForegroundColor White
Write-Host "  • Interactive security scanner" -ForegroundColor White
Write-Host ""
Write-Host "Dashboard URL: http://localhost:8501" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the dashboard" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Run the dashboard
try {
    python demo_dashboard.py
} catch {
    Write-Host ""
    Write-Host "✗ Dashboard stopped" -ForegroundColor Red
} finally {
    Write-Host ""
    Write-Host "Thank you for using LLMGuardian!" -ForegroundColor Green
    Read-Host "Press Enter to exit"
}
