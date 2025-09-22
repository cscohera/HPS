#check to see if microsoft fixed hash mismatch issue
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Host "choco is installed"
} else {
    Write-Host "Choco not installed"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

choco install sysinternals -y
choco install python3

