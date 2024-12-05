# Paths
$InstallerInfoPath = "C:\SandboxTest\InstallerInfo.json"
$Script3Path = "C:\SandboxTest\Script3-Test.ps1"
$Logo = "C:\SandboxTest\Personalisation\icon.jpg"
$wallpaperPath = "C:\SandboxTest\Personalisation\Wallpaper.jpg"

# Registry setting to specify wallpaper location and style (0 = Centered, 2 = Stretched)
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name Wallpaper -Value $wallpaperPath
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name WallpaperStyle -Value 2  # 2 for stretched
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name TileWallpaper -Value 0  # No tiling

# Force the wallpaper update by calling user32.dll to refresh the desktop parameters
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@
$winIniFlag = 0x01 -bor 0x02  # Using the correct bitwise OR operator
[Wallpaper]::SystemParametersInfo(20, 0, $wallpaperPath, $winIniFlag)


# Install BurntToast for Toast Notifications
$ModuleName = 'BurntToast'

# Check if the module is already installed and load it; otherwise, install and import it silently
Try {
    $null = Get-InstalledModule $ModuleName -ErrorAction Stop
    Write-Host "$ModuleName is already installed."
} Catch {
    Write-Host "$ModuleName is not installed. Installing now..."
    # Ensure NuGet is available for package installation
    if (-not (Get-PackageProvider -ListAvailable | Where-Object Name -eq "NuGet")) {
        Write-Host "NuGet package provider not found. Installing now..."
        Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -ErrorAction Stop
        Write-Host "NuGet package provider installed."
    }
    # Install the BurntToast module
    Install-Module -Name $ModuleName -Force -Scope CurrentUser -ErrorAction Stop
    Write-Host "$ModuleName module installed."
}

# Import the module
Try {
    Import-Module -Name $ModuleName -Force -ErrorAction Stop
    Write-Host "$ModuleName module loaded successfully."
} Catch {
    Write-Host "Failed to import the $ModuleName module."
    Throw
}

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

# Post a Toast Notification to advise that testing is starting
New-BurntToastNotification -Text " Preparing Install", " Preparing to install application from: $ApplicationInstallerPath" -AppLogo $Logo -UniqueIdentifier 'AppTest001'
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


# Post a Toast Notification to advise that testing is starting
New-BurntToastNotification -Text " Installation complete", " Installation of the application has completed successfully." -AppLogo $Logo -UniqueIdentifier 'AppTest001'
Write-Host "Application installation completed."

# Launch Script 3 for monitoring and hash collection
if (Test-Path $Script3Path) {
    Write-Host "Launching monitoring and testing script..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File $Script3Path" -NoNewWindow -Wait
    Write-Host "Monitoring and testing script completed."
} else {
    Write-Host "Monitoring script not found: $Script3Path" -ForegroundColor Red
    pause
}

Write-Host "Script 2 has finished execution."
pause
