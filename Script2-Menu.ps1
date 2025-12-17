<#
Soteria - In-sandbox GUI menu

Runs inside Windows Sandbox at logon. Collects user inputs, downloads the installer,
creates an isolated results subfolder, then launches Script3-Test.ps1.
#>

$Root = Join-Path $env:SystemDrive 'SandboxTest'
$InstallerInfoPath = Join-Path $Root 'InstallerInfo.json'
$Logo = Join-Path $Root 'Personalisation\icon.jpg'
$WallpaperPath = Join-Path $Root 'Personalisation\Wallpaper.jpg'
$Script3Path = Join-Path $Root 'Script3-Test.ps1'

function Set-SoteriaWallpaper {
    if (-not (Test-Path $WallpaperPath)) { return }
    try {
        Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name Wallpaper -Value $WallpaperPath -ErrorAction SilentlyContinue
        Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name WallpaperStyle -Value 2 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name TileWallpaper -Value 0 -ErrorAction SilentlyContinue

        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@
        $winIniFlag = 0x01 -bor 0x02
        [Wallpaper]::SystemParametersInfo(20, 0, $WallpaperPath, $winIniFlag) | Out-Null
    } catch {
        # non-fatal
    }
}

function Ensure-BurntToast {
    $ModuleName = 'BurntToast'
    try {
        Import-Module -Name $ModuleName -Force -ErrorAction Stop
        return
    } catch {}

    try {
        if (-not (Get-PackageProvider -ListAvailable | Where-Object Name -eq 'NuGet')) {
            Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
        }
        Install-Module -Name $ModuleName -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
        Import-Module -Name $ModuleName -Force -ErrorAction Stop
    } catch {
        # non-fatal
    }
}

Set-SoteriaWallpaper
Ensure-BurntToast

# GUI
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Soteria - Automated App Test & Benchmark'
$form.Size = New-Object System.Drawing.Size(720, 420)
$form.StartPosition = 'CenterScreen'
$form.Topmost = $true

$font = New-Object System.Drawing.Font('Segoe UI', 10)
$form.Font = $font

function Add-Label($text, $x, $y) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $text
    $l.AutoSize = $true
    $l.Location = New-Object System.Drawing.Point($x, $y)
    $form.Controls.Add($l)
}

function Add-TextBox($x, $y, $w, $default) {
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location = New-Object System.Drawing.Point($x, $y)
    $t.Size = New-Object System.Drawing.Size($w, 24)
    $t.Text = $default
    $form.Controls.Add($t)
    return $t
}

Add-Label 'Software download URL (exe / msi / msix):' 18 20
$txtUrl = Add-TextBox 18 44 670 ''

Add-Label 'Installer arguments (optional). Examples: /S  |  /quiet /norestart' 18 80
$txtArgs = Add-TextBox 18 104 670 ''

Add-Label 'Test duration (seconds):' 18 140
$txtTime = Add-TextBox 18 164 160 '120'

Add-Label 'Results subfolder name (for categorising runs):' 210 140
$txtSubfolder = Add-TextBox 210 164 478 'MyTest'

$chkKeepInstaller = New-Object System.Windows.Forms.CheckBox
$chkKeepInstaller.Text = 'Keep downloaded installer in results folder'
$chkKeepInstaller.AutoSize = $true
$chkKeepInstaller.Location = New-Object System.Drawing.Point(18, 206)
$chkKeepInstaller.Checked = $true
$form.Controls.Add($chkKeepInstaller)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = ''
$lblStatus.AutoSize = $true
$lblStatus.Location = New-Object System.Drawing.Point(18, 240)
$form.Controls.Add($lblStatus)

$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text = 'Download & Run Test'
$btnRun.Size = New-Object System.Drawing.Size(200, 36)
$btnRun.Location = New-Object System.Drawing.Point(18, 280)
$form.Controls.Add($btnRun)

$btnExit = New-Object System.Windows.Forms.Button
$btnExit.Text = 'Exit'
$btnExit.Size = New-Object System.Drawing.Size(120, 36)
$btnExit.Location = New-Object System.Drawing.Point(238, 280)
$form.Controls.Add($btnExit)

$btnExit.Add_Click({ $form.Close() })

$btnRun.Add_Click({
    $url = $txtUrl.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($url)) {
        [System.Windows.Forms.MessageBox]::Show('Please enter a download URL.', 'Soteria', 'OK', 'Warning') | Out-Null
        return
    }

    $testSeconds = 120
    [int]::TryParse($txtTime.Text.Trim(), [ref]$testSeconds) | Out-Null
    if ($testSeconds -lt 10) { $testSeconds = 10 }

    $sub = $txtSubfolder.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($sub)) { $sub = 'MyTest' }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $resultsRoot = Join-Path $Root 'Results'
    $runFolder = Join-Path (Join-Path $resultsRoot $sub) ('Run-' + $timestamp)
    New-Item -Path $runFolder -ItemType Directory -Force | Out-Null

    $fileName = Split-Path -Leaf $url
    if ($fileName -notmatch '\.(exe|msi|msix|msixbundle)$') {
        # Fall back to a neutral name (some URLs are parameterised)
        $fileName = 'Installer_' + $timestamp
    }

    $downloadPath = Join-Path $runFolder $fileName
    $lblStatus.Text = 'Downloading...'
    $form.Refresh()

    try {
        Invoke-WebRequest -Uri $url -OutFile $downloadPath -UseBasicParsing -ErrorAction Stop
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Download failed: $($_.Exception.Message)", 'Soteria', 'OK', 'Error') | Out-Null
        return
    }

    # If we didn’t get an extension, attempt to infer from content disposition
    if (-not ([IO.Path]::GetExtension($downloadPath))) {
        # leave as-is; Script3 will handle "unknown" extension gracefully
    }

    $installerArgs = $txtArgs.Text

    $info = [ordered]@{
        InstallerUrl        = $url
        InstallerPath       = $downloadPath
        InstallerArgs       = $installerArgs
        TestSeconds         = $testSeconds
        ResultsSubfolder    = $sub
        RunFolder           = $runFolder
        CreatedUtc          = (Get-Date).ToUniversalTime().ToString('o')
    }
    $info | ConvertTo-Json -Depth 5 | Set-Content -Path $InstallerInfoPath -Encoding UTF8

    try {
        if (Get-Command New-BurntToastNotification -ErrorAction SilentlyContinue) {
            New-BurntToastNotification -Text 'Soteria', 'Download complete. Starting install + benchmark...' -AppLogo $Logo -UniqueIdentifier 'Soteria001' | Out-Null
        }
    } catch {}

    $form.Hide()
    Start-Process -FilePath 'powershell.exe' -ArgumentList "-ExecutionPolicy Bypass -File `"$Script3Path`"" -NoNewWindow -Wait
    $form.Close()
})

[void]$form.ShowDialog()
