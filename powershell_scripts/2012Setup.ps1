# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force


if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Host "choco is installed"
} else {
    Write-Host "Choco not installed"
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    refreshenv
}

# Disable SMBv1 server component
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Disable SMBv1 client component
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "SMB1" -Value 0 -Force

Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -Value 5


choco install git.install -y
choco install sysinternals -y --params "/InstallDir:C:\Windows\System32\Sysprep\Panther\SSD"
choco install python3 -y
choco install everything -y --params "/InstallDir:C:\Windows\System32\Sysprep\Panther\SSD /run-on-system-startup"
choco install systeminformer -y "/InstallDir:C:\Windows\System32\Sysprep\Panther\SSD"


$env:Path += ";$($env:LocalAppData)\Programs\Python\Python3X\Scripts;$($env:LocalAppData)\Programs\Python\Python3X"
refreshenv


if (Test-Path .\requirements.txt) {
    pip install -r .\requirements.txt
}

New-Item -Path "C:\Blue" -ItemType Directory -Force
Invoke-WebRequest -Uri "https://github.com/ION28/BLUESPAWN/releases/download/v0.5.1-alpha/BLUESPAWN-client-x64.exe" -OutFile "C:\Blue\BLUESPAWN-client-x64.exe"


Function InstallHardeningKitty() {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'

    $releaseInfo = Invoke-WebRequest "https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest" -UseBasicParsing | ConvertFrom-Json
    $version = $releaseInfo.name.Substring(2)
    $downloadUrl = $releaseInfo.zipball_url

    $zipPath = "HardeningKitty$version.zip"
    $extractPath = ".\HardeningKitty$version"

    Invoke-WebRequest $downloadUrl -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

    $innerFolder = Get-ChildItem $extractPath | Where-Object { $_.PSIsContainer } | Select-Object -First 1
    Move-Item "$($innerFolder.FullName)\*" $extractPath -Force
    Remove-Item $innerFolder.FullName -Recurse -Force

    $modulePath = "$env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$version"
    New-Item -ItemType Directory -Path $modulePath -Force

    Copy-Item -Path "$extractPath\HardeningKitty.psd1", "$extractPath\HardeningKitty.psm1", "$extractPath\lists" -Destination $modulePath -Recurse

    Import-Module "$modulePath\HardeningKitty.psm1" -Force
}
InstallHardeningKitty
