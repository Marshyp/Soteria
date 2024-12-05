clear
# Paths and variables
$ApplicationInstallerPath = Read-Host "Enter the full path to the application installer"
$HashFilePath = "C:\SandboxTest\SoftwareHashes.txt"
$SandboxConfigPath = "C:\SandboxTest\TestSandbox.wsb"

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
$InstallerInfo | ConvertTo-Json | Set-Content -Path "C:\SandboxTest\InstallerInfo.json"

Write-Host "Installer information saved. Preparing sandbox configuration..."

# Generate a sandbox configuration file
@"
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\SandboxTest</HostFolder>
      <SandboxFolder>C:\SandboxTest</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\SandboxTest\Script2-Install.ps1</Command>
    <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\SandboxTest\Personalisation\set-wallpaper.ps1 $Wallpap</Command>
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