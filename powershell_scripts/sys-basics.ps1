#check to see if microsoft fixed hash mismatch issue
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "winget is installed"
} else {

    
    Write-Host "winget is not installed"
    $progressPreference = 'silentlyContinue'
    & "$PSScriptRoot\winget-install.ps1"
}

winget install "Microsoft.Sysinternals.Suite" --accept-source-agreements --accept-package-agreements

winget list "Microsoft.Sysinternals.Suite"
