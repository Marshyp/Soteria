# Paths and variables
$ApplicationInstallerPath = Read-Host "Enter the full path to the application installer"
$SoftwareName = [System.IO.Path]::GetFileNameWithoutExtension($ApplicationInstallerPath)  # Extract software name
$SoftwareFolderPath = "C:\SandboxTest\$SoftwareName"
$HashFilePath = "$SoftwareFolderPath\SoftwareHashes.txt"
$SandboxConfigPath = "$SoftwareFolderPath\TestSandbox.wsb"

# Create subfolder for software
if (-not (Test-Path $SoftwareFolderPath)) {
    New-Item -Path $SoftwareFolderPath -ItemType Directory
}

# Validate installer path
if (-not (Test-Path $ApplicationInstallerPath)) {
    Write-Host "Invalid application installer path: $ApplicationInstallerPath" -ForegroundColor Red
    exit
}

# Save installer path to a file for sandbox use
$InstallerInfo = @{
    InstallerPath = $ApplicationInstallerPath
    HashFilePath  = $HashFilePath
}
$InstallerInfo | ConvertTo-Json | Set-Content -Path "$SoftwareFolderPath\InstallerInfo.json"

Write-Host "Installer information saved. Preparing sandbox configuration..."

# Generate a sandbox configuration file
@"
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$SoftwareFolderPath</HostFolder>
      <SandboxFolder>$SoftwareFolderPath</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\SandboxTest\Script2-Install.ps1</Command>
  </LogonCommand>
</Configuration>
"@ | Set-Content -Path $SandboxConfigPath

Write-Host "Sandbox configuration file created at $SandboxConfigPath."

# Launch the sandbox
Write-Host "Launching Windows Sandbox for software testing..."
Start-Process -FilePath "C:\Windows\System32\WindowsSandbox.exe" -ArgumentList $SandboxConfigPath -NoNewWindow

# Notify user and wait for sandbox to close
Write-Host "Windows Sandbox launched. Waiting for completion..."
while (Get-Process -Name "WindowsSandbox" -ErrorAction SilentlyContinue) {
    Start-Sleep -Seconds 5
}

Write-Host "Sandbox has completed testing. Software testing process is now complete."
