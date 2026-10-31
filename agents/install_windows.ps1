# Windows PowerShell Installation & Setup Script for Network Testing Agents
# Compatible with Windows 10 & Windows 11

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Electrical Interference Investigation Agent Installer" -ForegroundColor Cyan
Write-Host "  Platform: Windows 10/11" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Verify Python Installation
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    $pythonCmd = Get-Command py -ErrorAction SilentlyContinue
}

if (-not $pythonCmd) {
    Write-Error "Python 3 is not installed or not in PATH. Please install Python 3.9+ from python.org or the Microsoft Store."
    exit 1
}

Write-Host "[+] Found Python: $($pythonCmd.Source)" -ForegroundColor Green

# 2. Create local virtual environment
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

if (-not (Test-Path "$scriptDir\.venv")) {
    Write-Host "[*] Creating Python virtual environment in $scriptDir\.venv..." -ForegroundColor Yellow
    & python -m venv "$scriptDir\.venv"
}

# 3. Install agent dependencies
Write-Host "[*] Installing required Python libraries..." -ForegroundColor Yellow
& "$scriptDir\.venv\Scripts\python.exe" -m pip install --upgrade pip
& "$scriptDir\.venv\Scripts\python.exe" -m pip install -r "$scriptDir\requirements.txt"

# 4. Check for iperf3
$iperfCmd = Get-Command iperf3 -ErrorAction SilentlyContinue
if ($iperfCmd) {
    Write-Host "[+] iperf3 is installed at: $($iperfCmd.Source)" -ForegroundColor Green
} else {
    Write-Host "[i] Optional: iperf3 binary not found in PATH." -ForegroundColor Yellow
    Write-Host "    The agent will automatically use its built-in pure-Python throughput engine." -ForegroundColor Yellow
    Write-Host "    To install native iperf3: winget install -e --id iperf3.iperf3" -ForegroundColor Yellow
}

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  Installation Completed Successfully!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "To run Device 1 (Sender):" -ForegroundColor White
Write-Host "  & `"$scriptDir\.venv\Scripts\python.exe`" `"$scriptDir\sender\sender_agent.py`" --server http://<FLASK_IP>:5000" -ForegroundColor Cyan
Write-Host ""
Write-Host "To run Device 2 (Receiver):" -ForegroundColor White
Write-Host "  & `"$scriptDir\.venv\Scripts\python.exe`" `"$scriptDir\receiver\receiver_agent.py`" --server http://<FLASK_IP>:5000" -ForegroundColor Cyan
