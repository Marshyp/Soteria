# Run from an elevated PowerShell session.
Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online
Write-Host "Restart Windows if prompted."
