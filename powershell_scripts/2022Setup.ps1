
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Host "choco is installed"
} else {
    Write-Host "Choco not installed"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

# Disable SMBv1 server component
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Disable SMBv1 client component
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "SMB1" -Value 0 -Force

Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -Value 5


choco install 7zip -y --params "/InstallDir:C:\SSD\"
$installer = "C:\Temp\Snort_2_9_20_Installer.x64.exe"
Invoke-WebRequest -Uri https://snort.org/downloads/snort/Snort_2_9_20_Installer.x64.exe -OutFile $installer
Start-Process -FilePath $installer -ArgumentList "/S" -Wait

$installer2 = "C:\Temp\npcap-1.84.exe"
Invoke-WebRequest -Uri https://npcap.com/dist/npcap-1.84.exe -OutFile $installer2
Start-Process -FilePath $installer2 -ArgumentList "/S" -Wait

Invoke-WebRequest -Uri https://raw.githubusercontent.com/thereisnotime/Snort-Default-Windows-Configuration/master/snort.conf -OutFile "C:\"

# Path to existing Snort config
$snortConfPath     = "C:\Snort\etc\snort.conf"

# Path to your custom config file
$customConfSource  = "C:\snort.conf"


# Replace with your version
if (Test-Path $customConfSource) {
    Write-Host "Copying your custom snort.conf..."
    Copy-Item -Path $customConfSource -Destination $snortConfPath -Force
    Write-Host "snort.conf has been replaced successfully."
} else {
    Write-Error "Custom config file not found at $customConfSource"
    exit 1
}

New-Item -Path "C:\Snort\rules\black.list" -ItemType File -Force
New-Item -Path "C:\Snort\rules\white.list" -ItemType File -Force

$sevenZipPath = "C:\SSD\7-Zip\7z.exe"
$downloadPath = "C:\snort2-community-rules.tar"
$extractPath = "C:\snortrules"
$snortInstallPath = "C:\Snort"
$rulesDest = "$snortInstallPath\rules"
$preprocDest = "$snortInstallPath\preproc_rules"
$snortConf = "$snortInstallPath\etc\snort.conf"

# Download the file (if not already downloaded)

Invoke-WebRequest -Uri "https://github.com/thereisnotime/Snort-Rules/blob/master/snort2-community-rules.tar?raw=true" -OutFile $downloadPath

# Extract .tar archive
Write-Host "Extracting .tar archive..."
& $sevenZipPath x $downloadPath -o$extractPath -y | Out-Null

# Copy rules
Write-Host "Copying rules to Snort directory..."
New-Item -ItemType Directory -Force -Path $rulesDest | Out-Null
Copy-Item -Path "$extractPath\rules\*" -Destination $rulesDest -Recurse -Force

# Copy preproc_rules if any
if (Test-Path "$extractPath\preproc_rules") {
    New-Item -ItemType Directory -Force -Path $preprocDest | Out-Null
    Copy-Item -Path "$extractPath\preproc_rules\*" -Destination $preprocDest -Recurse -Force
}

# Update snort.conf RULE_PATH
if (Test-Path $snortConf) {
    (Get-Content $snortConf) | ForEach-Object {
        if ($_ -match '^\s*var\s+RULE_PATH') {
            "var RULE_PATH $rulesDest"
        } else {
            $_
        }
    } | Set-Content $snortConf
    Write-Host "Updated snort.conf RULE_PATH."
} else {
    Write-Host "snort.conf not found at $snortConf"
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
