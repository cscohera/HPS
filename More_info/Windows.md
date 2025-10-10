
Security policies: Make sure to back up GPOS and re run gpo script
Remove change password
Rename administrator
Prohibit access to control panel
Prevent access to the command prompt
Deny all removable storage access
Prohibit users from installing unwanted software
Reinforce guest account status settings
Do not store LAN manager hash values on next password changes
Audit directory service access and audit directory service changes

Reenabling Windows defender

Re-enable Real-Time Protection via PowerShell:
PowerShell

Set-MpPreference -DisableRealtimeMonitoring 0

or

Fix Registry Keys:

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Value 0

Or

Restart the Service:


Critical Defensive Strategies
CHANGE ALL PASSWORDS IMMEDIATELY!
Uninstall unnecessary programs 
Disable bluetooth and beacons
Lugsar change passwords via script
 Scheduled Tasks:
Check for any task scheduled in schtasks.exe or GUI

Startup Folders & Registry:
	HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run and the equivalent HKEY_LOCAL_MACHINE key.

Check Services

Remove a service: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-service?view=powershell-7.5


Put lgpo in folder with policies name 1 and 2
Then cd file path
LGPO.exe /g 1
Do with all other important policys
Do dod in both windows fire wall and gpedit.msc

Task Manager

Re enable task manager:  REG add  HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 0 /f



Firewall

Re-enable all firewall profiles (Domain, Private, Public):
netsh advfirewall set allprofiles state on
Or
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True


If they cook us and do not have ability to Re-enable firewall we will use
Cmd admin and remove quotes:
route ADD “Attacker IP” MASK 255.255.255.255 127.0.0.1
Or use -p with command so it is persistent if pc restarted
route -p ADD “Attacker IP” MASK 255.255.255.255 127.0.0.1
Check route is in place with “route print” and use 
route DELETE “ip”
If needed



Turn the firewall on or off
Go to Settings > Windows Security > Firewall & network protection and select On or Off. 
Configure a specific port
Go to Windows Defender Firewall, click Inbound Rules, then New Rule. Select the port, enter the port number, and choose to allow or block the connection. 
Configure outbound connections
Repeat the steps for configuring a specific port, but select Outbound Rules instead of Inbound Rules. 
Reset the firewall
Go to Control Panel > System and Security > Windows Defender Firewall and click Restore Defaults. 


Device security/ memory integrity/ turn on

App and browser control/ force randomization for images/ on by default

Autoplay off

Config User Account Control to limit privileges
Implement fire wall rules

Seeing connections to the server that may need to be blocked
See remotely connected computers: Scan with netstat -ba its goated or using netstat -ano
Block ips via cmd: netsh advfirewall firewall add rule name="Block IP" dir=out action=block remoteip=IP
https://superuser.com/questions/1040874/how-to-prevent-remote-connections-from-another-machine

Use: netstat -a for ports
Local security policy
Lockout policy
Account lockout duration 15 mins
Account lockout threshold: 10 failed authentication attempts
Reset counter after: 15 mins

Windows defender antivirus:
Turn off windows defender antivirus: disabled


 Enumerate users and groups
        Change passwords for any service accounts
        Back up critical services
        Download tools
        Patch Windows and Critical service
        Disable unneeded software and services
        Check for Backdoors using TCP Viewer, Process Explorer, Autoruns, Everything





    Enumerate users and groups
        Run lusrmgr.msc displays users and groups for local machine
        Or do via powershelling as administrator if there are lots of users
        Change all user passwords
        Change Administrator account password
               
    Change passwords for any service accounts
        Varies by service on what to do

    Backup Critical Services
        Varies by service on what to do, but most of the time just copy the files to a folder and zip it somewhere people wouldn’t look.


    Patch Windows and Critical services
        Check the patch checklist for specific process to patch OS and services

    Disable unneeded software and services

    Check for Backdoors using TCP Viewer, Process Explorer, Autoruns, Everything
        Don’t just kill anything because the scoring engine may need it but do research and view logs
        Usually sort by publisher (look for not verified, but some apps are just not)
        For Everything sort by last modified



Add Script block logging for powershell

Snort:

https://github.com/thereisnotime/Snort-Default-Windows-Configuration

https://medium.com/linode-cube/5-essential-steps-to-hardening-your-mysql-database-591e477bbbd7

