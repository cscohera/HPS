
#work in progress need to test
while ($true){
    $newUser = Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4720 } | 
    Select-Object -Property TimeCreated, @{Name='User';Expression={$_.Properties[5].Value}}, @{Name='IP';Expression={$_.Properties[18].Value}}


    Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true }

}