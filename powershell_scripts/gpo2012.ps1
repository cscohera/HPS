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
    "56a863a9-875e-4185-98a7-b882c64b5ce5",  # Block Office apps from creating child processes
    "3b576869-a4ec-4529-8536-b80a7769e899",  # Block credential stealing from LSASS
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",  # Block executable content from email/webmail
    "26190899-1602-49e8-8b27-eb1d0a1ce869"   # Block process creation from PSExec and WMI
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