

[CmdletBinding()]
param(
    [string]$OutRoot = "C:\HelloReport",
    [switch]$IncludeMySQL = $true,
    [switch]$IncludeFTP = $true
)

function Ensure-Dir($p){ if(-not (Test-Path $p)) { New-Item -Path $p -ItemType Directory | Out-Null } }

$ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
$outDir = Join-Path $OutRoot $ts
Ensure-Dir $outDir

# helper for writing HTML
function Write-ReportFiles($name, $objects) {
    $html = Join-Path $outDir ("$name.html")
    $objects | ConvertTo-Html -Title $name -PreContent "<h2>$name</h2><p>Generated $ts</p>" | Out-File -FilePath $html -Encoding utf8
    Write-Host "Wrote: $html"
}

Write-Host "Discovery start: $ts" -ForegroundColor Cyan

# 1) Local user accounts (enabled, last logon, admin group membership)
Write-Host "Enumerating local accounts..."
$users = Get-LocalUser | Select-Object Name,Enabled,Description,LastLogon
$adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object Name, ObjectClass
Write-ReportFiles -name "LocalUsers" -objects $users
Write-ReportFiles -name "LocalAdmins" -objects $adminGroup

# 2) Scheduled Tasks
Write-Host "Enumerating scheduled tasks..."
try {
    $tasks = Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Actions,@{n='Principal';e={$_.Principal.UserId}},@{n='LastRunTime';e={(Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath).LastRunTime}} -ErrorAction Stop
} catch {
    # fallback to schtasks
    $tasks = schtasks /Query /FO LIST /V | Out-String
}
if ($tasks -is [System.Array]) { Write-ReportFiles -name "ScheduledTasks" -objects $tasks } else { $tasks | Out-File (Join-Path $outDir "ScheduledTasks.txt") }

# 3) Services configured Auto/AutoStart and binary path
Write-Host "Enumerating auto-start services..."
$svc = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.StartMode -in @('Auto','Auto (Delayed Start)') } | Select-Object Name,DisplayName,StartMode,State,StartName,PathName
Write-ReportFiles -name "AutoServices" -objects $svc

# 4) Run/RunOnce autoruns (HKLM & HKCU) + Winlogon shell/userinit
Write-Host "Enumerating Run/RunOnce and Winlogon..."
$autoruns = @()
$autorunKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($k in $autorunKeys) {
    if (Test-Path $k) {
        try {
            Get-ItemProperty -Path $k | ForEach-Object {
                $_.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } |
                ForEach-Object {
                    [PSCustomObject]@{
                        Key = $k
                        Name = $_.Name
                        Value = $_.Value
                    }
                }
            } | ForEach-Object { $autoruns += $_ }
        } catch {}
    }
}
# Winlogon entries
$winlogon = @{}
$wlPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if (Test-Path $wlPath) {
    $winlogon = Get-ItemProperty -Path $wlPath | Select-Object Shell,Userinit,Notify
}
Write-ReportFiles -name "Autoruns" -objects $autoruns
if ($winlogon) { $winlogon | ConvertTo-Json | Out-File (Join-Path $outDir "Winlogon.json") }

# 5) WMI Event Consumers & Filters (classic WMI persistence vector)
Write-Host "Checking WMI event consumers & filters..."
$wmifilters = Get-CimInstance -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Select-Object Name,Query,QueryLanguage,EventNamespace
$wmiconsumers = Get-CimInstance -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue | Select-Object *
$wmiBindings = Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object *
Write-ReportFiles -name "WMI_Filters" -objects $wmifilters
Write-ReportFiles -name "WMI_Consumers" -objects $wmiconsumers
Write-ReportFiles -name "WMI_Bindings" -objects $wmiBindings

# 6) Scheduled Task Folders (we already enumerated tasks, but also check actions for suspicious executables)
Write-Host "Checking scheduled task actions for suspicious paths..."
$taskSuspicious = @()
if ($tasks -isnot [string]) {
    foreach ($t in $tasks) {
        if ($t.Actions) {
            $t.Actions | ForEach-Object {
                $taskSuspicious += [PSCustomObject]@{
                    TaskName = $t.TaskName
                    Action = $_
                }
            }
        }
    }
    if ($taskSuspicious.Count -gt 0) { Write-ReportFiles -name "TaskActions" -objects $taskSuspicious }
}

# 7) Persistence via Services/Drivers (unsigned, unusual paths)
Write-Host "Checking services for suspicious path locations (Temp, AppData, Users profile)..."
$suspSvc = $svc | Where-Object { $_.PathName -match '\\Temp\\|\\AppData\\|Users\\' }
Write-ReportFiles -name "SuspiciousServicePaths" -objects $suspSvc

# 8) SSH keys / OpenSSH (if installed)
Write-Host "Checking for OpenSSH server and authorized_keys in profiles..."
$openssh = Get-Service -Name sshd -ErrorAction SilentlyContinue
$sshAuthFiles = Get-ChildItem -Path C:\Users\*\.ssh\authorized_keys -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime
Write-ReportFiles -name "OpenSSH" -objects @($openssh, $sshAuthFiles)

# 9) Firewall rules added recently (last 7 days)
Write-Host "Checking firewall rules created/modified in last 7 days..."
try {
    $fw = Get-NetFirewallRule | Where-Object { ($_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue) -or ($_.CreationTime -and ($_.CreationTime -gt (Get-Date).AddDays(-7))) } | Select-Object DisplayName,Name,Enabled,Direction,Action,Profile,CreationTime
    Write-ReportFiles -name "FirewallRecent" -objects $fw
} catch { Write-Host "Firewall audit failed: $_" }

# 10) Autorun services in registry image list
Write-Host "Scanning common autorun registry locations for suspicious entries..."
$regLocations = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\System\CurrentControlSet\Services',
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
)
# Dump services (we already did) + registry keys with unusual paths
# For brevity, export Services registry subtree
$svcRegDump = Join-Path $outDir "ServicesRegistry.txt"
reg export "HKLM\SYSTEM\CurrentControlSet\Services" $svcRegDump /y | Out-Null
Write-Host "Exported Services registry to $svcRegDump (large file)"



Write-Host "Discovery complete. Reports in $outDir" -ForegroundColor Green