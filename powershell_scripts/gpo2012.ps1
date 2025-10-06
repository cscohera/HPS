# =============== BASIC INFO ===============
Write-Host "Starting hardening against persistence..." -ForegroundColor Cyan



# =============== BLOCK STARTUP FOLDER EXECUTION ===============
# Requires Software Restriction Policies or AppLocker
# Note: SRP Example
$srpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
New-Item -Path $srpPath -Force | Out-Null
Set-ItemProperty -Path $srpPath -Name "Levels" -Value 262144
Set-ItemProperty -Path $srpPath -Name "PolicyScope" -Value 0
Set-ItemProperty -Path $srpPath -Name "TransparentEnabled" -Value 1
Set-ItemProperty -Path $srpPath -Name "AuthenticodeEnabled" -Value 1
Set-ItemProperty -Path $srpPath -Name "DefaultLevel" -Value 0x40000

# Disallow %APPDATA% and %TEMP% execution
$disallowedPaths = @(
    "%AppData%\*",
    "%LocalAppData%\Temp\*",
    "%UserProfile%\Downloads\*"
)

$ruleID = 262144
foreach ($path in $disallowedPaths) {
    $subkey = "$srpPath\0\Paths\$ruleID"
    New-Item -Path $subkey -Force | Out-Null
    New-ItemProperty -Path $subkey -Name "ItemData" -Value $path -PropertyType String -Force
    New-ItemProperty -Path $subkey -Name "SaferFlags" -Value 0 -PropertyType DWord -Force
    $ruleID++
    Write-Host "Blocked execution from: $path"
}

# =============== DISABLE WINDOWS SCRIPT HOST ===============
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Force
Write-Host "Disabled Windows Script Host"

# =============== SET POWERSHELL EXECUTION POLICY ===============
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force
Write-Host "Set PowerShell execution policy to AllSigned"

# =============== ENABLE AUDIT POLICIES FOR PERSISTENCE ===============
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Scheduled Task Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
Write-Host "Enabled key audit policies"

# =============== CONFIGURE DEFENDER ASR RULES ===============
# Ensure Defender is installed and running
$asrRules = @(
    
    "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Block abuse of exploited vulnerable signed drivers";
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader from creating child processes";
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes";
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)";
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail";
    "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content";
    "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content";
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes";
    "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication application from creating child processes";
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block persistence through WMI event subscription";
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations originating from PSExec and WMI commands";
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros";
    "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced protection against ransomware";
    "A8F5898E-1DC8-49A9-9878-85004B8A61E6" = "Block Webshell creation for Servers";
)

foreach ($rule in $asrRules) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions Enabled
    Write-Host "Enabled Defender ASR rule: $rule"
}

# =============== DISABLE MACROS IN OFFICE (REGISTRY) ===============
$officeVersions = @("16.0", "15.0", "14.0") # Office 2016, 2013, 2010
foreach ($ver in $officeVersions) {
    $macroPath = "HKCU:\Software\Microsoft\Office\$ver\Word\Security"
    New-Item -Path $macroPath -Force | Out-Null
    Set-ItemProperty -Path $macroPath -Name "VBAWarnings" -Value 4  # 4 = Disable all macros with notification
    Write-Host "Restricted macros for Office version $ver"
}

Write-Host "`n✅ Hardening complete. Some changes may require restart or GPO refresh." -ForegroundColor Green