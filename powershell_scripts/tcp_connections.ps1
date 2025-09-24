while ($true) {
    $outputFile = "C:\whosthere.csv"

    $establishedConnections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | 
    Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State 
    
    $listeningConnections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } |
    Select-Object -Property LocalAddress, LocalPort, State

    $failedConnections = Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4625 } | 
    Select-Object -Property TimeCreated, @{Name='User';Expression={$_.Properties[5].Value}}, @{Name='IP';Expression={$_.Properties[18].Value}}

    # Combine all data into a single object
    $combinedData = [PSCustomObject]@{
    EstablishedConnections = $establishedConnections
    ListeningConnections = $listeningConnections
    OutboundTraffic = $outboundTraffic
    FailedConnections = $failedConnections
    }

    $combinedData | Export-Csv -Path $outputFile -NoTypeInformation

    Start-Sleep -Seconds 300  #wait for 5 minutes before running again
}