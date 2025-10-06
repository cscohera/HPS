
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Host "choco is installed"
} else {
    Write-Host "Choco not installed"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

#maybe bluespawn or commodo kill switch
# Set-SmbServerConfiguration -EnableSMB1Protocol -Confirm:$false
New-Item -Path "C:\Blue" -ItemType Directory -Force 

Invoke-WebRequest -Uri https://github.com/ION28/BLUESPAWN/releases/download/v0.5.1-alpha/BLUESPAWN-client-x64.exe -OutFile "C:\Blue\BLUESPAWN-client-x64.exe"
# NEED TO INSTALL GIT choco install git.install -y
choco install sysinternals -y --params "/InstallDir:C:\SSD\"
choco install python3 -y
choco install everything -y --params "/start-menu-shortcuts /run-on-system-startup" 
choco install systeminformer -y "/InstallDir:C:\SSD\"
pip install -r requirements.txt

Function InstallHardeningKitty() {
    $Version = (((Invoke-WebRequest "https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest" -UseBasicParsing) | ConvertFrom-Json).Name).SubString(2)
    $HardeningKittyLatestVersionDownloadLink = ((Invoke-WebRequest "https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest" -UseBasicParsing) | ConvertFrom-Json).zipball_url
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest $HardeningKittyLatestVersionDownloadLink -Out HardeningKitty$Version.zip
    Expand-Archive -Path ".\HardeningKitty$Version.zip" -Destination ".\HardeningKitty$Version" -Force
    $Folder = Get-ChildItem .\HardeningKitty$Version | Select-Object Name -ExpandProperty Name
    Move-Item ".\HardeningKitty$Version\$Folder\*" ".\HardeningKitty$Version\"
    Remove-Item ".\HardeningKitty$Version\$Folder\"
    New-Item -Path $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version -ItemType Directory
    Set-Location .\HardeningKitty$Version
    Copy-Item -Path .\HardeningKitty.psd1,.\HardeningKitty.psm1,.\lists\ -Destination $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\ -Recurse
    Import-Module "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\HardeningKitty.psm1"
}
InstallHardeningKitty
