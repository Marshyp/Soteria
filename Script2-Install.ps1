# Paths
$InstallerInfoPath = "C:\SandboxTest\InstallerInfo.json"
$Script3Path = "C:\SandboxTest\Script3-Test.ps1"

# Validate InstallerInfo file
if (-not (Test-Path $InstallerInfoPath)) {
    Write-Host "Installer info file not found: $InstallerInfoPath" -ForegroundColor Red
    exit
}

# Load installer details
$InstallerInfo = Get-Content -Path $InstallerInfoPath | ConvertFrom-Json
$ApplicationInstallerPath = $InstallerInfo.InstallerPath

if (-not (Test-Path $ApplicationInstallerPath)) {
    Write-Host "Installer file not found in the sandbox: $ApplicationInstallerPath" -ForegroundColor Red
    exit
}

Write-Host "Preparing to install application from: $ApplicationInstallerPath"

# Detect installer type (EXE or MSI) and install
if ($ApplicationInstallerPath -like "*.msi") {
    Write-Host "Detected MSI installer. Installing silently..."
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$ApplicationInstallerPath`" /quiet /norestart" -Wait
} elseif ($ApplicationInstallerPath -like "*.exe") {
    Write-Host "Detected EXE installer. Installing silently..."
    Start-Process -FilePath $ApplicationInstallerPath -ArgumentList "/S" -Wait
} else {
    Write-Host "Unknown installer type. Installation aborted." -ForegroundColor Red
    exit
}

Write-Host "Application installation completed."

# Launch Script 3 for monitoring and hash collection
if (Test-Path $Script3Path) {
    Write-Host "Launching monitoring and testing script..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File $Script3Path" -NoNewWindow -Wait
    Write-Host "Monitoring and testing script completed."
} else {
    Write-Host "Monitoring script not found: $Script3Path" -ForegroundColor Red
}

Write-Host "Script 2 has finished execution."
