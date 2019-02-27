<#
.SYNOPSIS
    Reboots computers as jobs.

.DESCRIPTION
    This script reboots computers as a job.  If the computer does not respond to a ping the script attempts to send a wake on lan (magic) packet to the computer,
    waits for the computer to wake up, and then reboots it.  A report is emailed at the end of the script as well as saved to the restarts.log file.

.EXAMPLE
    .\Invoke-ParallelComputerReboots.ps1

.NOTES

    Author: Jason Dillman
    Revision Date: 2-26-2019
    Version: 4.0.0
    Author Date: 2-24-2017

    Invoke-WakeClient needs to be run with administrative permissions on Server 2012 R2 in my testing.

    Inspired from "Restart computers in batches as jobs" (https://gallery.technet.microsoft.com/scriptcenter/Restart-computers-in-a122b3cc) by Bigteddy
    WOL functionality added from "DHCP Wake on Lan Tool for Powershell v4" (https://gallery.technet.microsoft.com/scriptcenter/Wake-on-Lan-for-DHCP-tool-3c2d8adf) by Jacob Sommerville

    Changelog
    4.0.0: Date: 02-26-2019:  Significant code re-write.  Added comments to the beginning of all functions, changed the email report from text to an HTML table, fixed a bug where reboots 
           weren't detected if a computer reboots too fast, changed formatting to more 'standard' PowerShell formatting, and removed the external settings file.
    3.3.0: Added function to create restore point prior to reboot.
    3.2.1: Removed for-each loop to calculate the number or rows in the computer list file (used for determining number of jobs to run) and replaced with .count method.
#>

<#  Declare variables #>
<# Run the following code as administrator to update DHCP_Clients.csv for hostname to MAC address resolution.  
$DHCPScopeName = '10.0.0.0'
Get-DhcpServerv4Lease -ScopeId $DHCPScopeName | 
    Select-Object -Property @{ name = 'Host'       ; expression = { $_.'HostName' } } , 
                            @{ name = 'MACAddress' ; expression = { $_.'ClientID' } } | 
        Export-Csv -Path 'C:\Scripts\Dependencies\DHCP_Clients.csv' -NoTypeInformation
#>
$computersToReboot    = Get-Content -Path 'C:\Scripts\Dependencies\Computers-To-Reboot.txt' | Sort-Object
$computerMacAddresses = Import-Csv -Path 'C:\Scripts\Dependencies\DHCP_Clients.csv'
$logFilePath          = 'C:\Scripts\restarts.log'

<#  Email settings #>
$recipient         = 'you@yourdomain.com'
$sender            = 'alerts@mydomain.com'
$smtpServer        = 'smtp.mydomain.com'
$subject           = 'Workstation Reboots'
$userName          = 'alerts@mydomain.com'
$password          = ConvertTo-SecureString -String 'SuperSecretPasswordNumber12!' -AsPlainText -Force
$port              = 587
$credential        = New-Object System.Management.Automation.PSCredential $userName,$password
[string]$emailBody = ''

Import-Module 'C:\Scripts\Report-Functions.psm1'

function Invoke-RestartJob {
    <#     
    .SYNOPSIS      
        Creates a job to reboot a computer.

    .DESCRIPTION    
        Creates a job that reboots a computer if it's online, attempts to wake the computer via WOL if it's not, and creates a 
        system restore point prior to reboot if the computer is not a server.  Errors are logged and returned as hash tables.

    .EXAMPLE    
        Invoke-RestartJob $computersToReboot $computerMacAddress
        $computersToReboot | Invoke-RestartJob -Computer $_ -MAC $computerMacAddress

    .NOTES
        Written by Jason Dillman on 2-25-2019
        Rev. 1.0
    #>
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName)][Alias('Computer')]$computerName,
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName)][Alias('MAC')]$computerMacAddress
    )

    Start-Job  -Name $computerName -ArgumentList $computerName, $computerMacAddress -ScriptBlock {
        Param (
            [Parameter(Mandatory=$true,ValueFromPipeline=$true)][PSObject]$computerName, 
            [Parameter(Mandatory=$true,ValueFromPipeline=$true)][PSObject]$computerMacAddress
        )

        function New-RemoteCheckpoint{
            Param (
                [Parameter(Mandatory=$true,ValueFromPipeline=$true)][PSObject]$remoteComputer,  
                [Parameter(Mandatory=$true,ValueFromPipeline=$true)][PSObject]$Stopwatch
            )
            <#   
            .SYNOPSIS    
                Create a System Restore point on a remote computer
            .DESCRIPTION
                Creates a System Restore point on each $remoteComputer supplied with a uniform name.  A check is then run to verify the
                restore point created successfully and, if not, a message is returned.
            .PARAMETER remoteComputer
                The name of the computer to create a restore point on
            .PARAMETER stopWatch
                A timer to track how long the jobs take
            #>
            $today = Get-Date -Format d

            Foreach ($computerName in $remoteComputer) {
                Invoke-Command -ComputerName $computerName -ScriptBlock {
                    $today = Get-Date -Format d
                    Checkpoint-Computer -Description "Weekly auto-created checkpoint $today" -ErrorAction SilentlyContinue
                }
            
                # Verify that the restore point was created
                $restore = Invoke-Command -ComputerName $computerName -ScriptBlock {Get-ComputerRestorePoint} -ErrorAction SilentlyContinue
                if ($restore.Description -notmatch $today) {
                    $timer = $StopWatch.Elapsed.ToString('hh\:mm\:ss')
                    @{
                        'Computer Name'  = $computerName
                        'Error'          = 'Restore Point creation failed'
                        'Execution Time' = $timer
                    }
                }
            }
        } # end New-RemoteCheckpoint function

        function Invoke-WakeClient {
            <#     
            .SYNOPSIS      
                Send a WOL packet to a provided computer

            .DESCRIPTION    
                Send a WOL packet to a provided computer.  Requires the computer name and a table to computer names with
                their MAC addresses.

            .EXAMPLE    
                Invoke-WakeClient $computerName $computerMacAddress
                $computerName | Invoke-WakeClient -MAC $computerMacAddress

            .NOTES
                Written by Jason Dillman on 2-25-2019
                Rev. 1.0
            #>
            Param (
                [Parameter(Mandatory=$true,ValueFromPipeline=$true)][PSObject]$computerName,  
                [Parameter(Mandatory=$true,ValueFromPipeline=$true)][PSObject][Alias('MAC')]$computerMacAddress
            )

            #The Send-WOL function was snagged directly from Barry Chum's code  
            #http://gallery.technet.microsoft.com/scriptcenter/Send-WOL-packet-using-0638be7b 
            
            function Send-WOL {  
                <#   
                .SYNOPSIS    
                    Send a WOL packet to a broadcast address  
                .PARAMETER mac  
                The MAC address of the device that need to wake up  
                .PARAMETER ip  
                The IP address where the WOL packet will be sent to  
                .EXAMPLE   
                Send-WOL -mac 00:11:32:21:2D:11 -ip 192.168.8.255   
                #>  
  
                Param (
                    [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$mac, 
                    [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$broadcast,
                    [int]$port=9
                )  
                $broadcast = [Net.IPAddress]::Parse($broadcast)  
                $mac=(($mac.replace(":","")).replace("-","")).replace(".","")  
                $target=0,2,4,6,8,10 | Foreach-Object {[convert]::ToByte($mac.substring($_,2),16)}  
                $packet = (,[byte]255 * 6) + ($target * 16)  
    
                $UDPclient = new-Object System.Net.Sockets.UdpClient  
                $UDPclient.Connect($broadcast,$port)  
                [void]$UDPclient.Send($packet, 102)   
            } # end of Send-WOL function  

            Send-WOL -mac $computerMacAddress.MACAddress -Broadcast $computerMacAddress.Broadcast
        } # end of Invoke-WakeClient function

        function Invoke-RemoteRestart {
            <#     
            .SYNOPSIS      
                Reboots a remote computer.

            .DESCRIPTION    
                Reboots the computer provided.  After sending the reboot command the function waits until the computer reports
                it's last boot time to be later than the start of the script, or 20 minutes, whichever comes first.
                If the computer fails to report a last boot time more recent that the script start time a hash table is 
                returned with this error as well as the duration of the stopwatch passed to the function.

            .EXAMPLE    
                Invoke-RemoteRestart $computerName $jobStartTime $stopWatch
                $computerName | Invoke-WakeClient -MAC $computerMacAddress

            .NOTES
                Written by Jason Dillman on 2-25-2019
                Rev. 1.0
            #>
            Param (
                [Parameter(Mandatory=$true,ValueFromPipeline=$true)][PSObject]$remoteComputer,
                [Parameter(Mandatory=$true,ValueFromPipeline=$true)][PSObject]$scriptStartTime,
                [Parameter(Mandatory=$true,ValueFromPipeline=$true)][PSObject]$stopWatch
            )
            $count = 0
            Restart-Computer $remoteComputer -Force -ErrorAction Stop
            do {
                $lastBoot = Invoke-Command -ComputerName $remoteComputer  -ErrorAction SilentlyContinue -ScriptBlock {
                    Get-CimInstance -ClassName win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime
                }
                $count++
                Start-Sleep -Seconds 10
            } until ( ($scriptStartTime -lt $lastBoot) -or ($count -ge 120)) 
                
            if ($count -ge 120) {
                $Stopwatch.Stop()
                $timer = $StopWatch.Elapsed.ToString('hh\:mm\:ss')
                @{
                    'Computer Name'  = $remoteComputer
                    'Error'          = 'Did not reboot'
                    'Execution Time' = $timer
                }
            }
        } #end function Invoke-RemoteRestart

        <########  
                    Start of Job  
                                   #######>

        # creating a stopwatch so we know how long each computer takes to reboot
        $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
        $StopWatch.Start()
        $jobStartTime = Get-Date
        # make sure the computer responds to a ping
        if (Test-Connection $computerName -quiet -count 2) {
            try {
                $osVersion = Invoke-Command $computerName -ScriptBlock {Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption}
                if ($osVersion -notlike '*Server*') {
                    New-RemoteCheckpoint $computerName $stopWatch
                }
                Invoke-RemoteRestart $computerName $jobStartTime $stopWatch
            } catch {
                $Stopwatch.Stop()
                $timer = $StopWatch.Elapsed.ToString('hh\:mm\:ss')
                [ordered] @{
                        'Computer Name'  = $computerName
                        'Error'          = 'Restart-Computer failed'
                        'Execution Time' = $timer
                    }
            }
        # if the computer didn't respond to the initial ping, try to send wake on lan
        } else {
            $count = 0
            try {
                Invoke-WakeClient $computerName $computerMacAddress
                do {
                    if ( -not (Test-Connection $computerName -quiet -count 2)) { 
                        $count++
                        Start-Sleep -Seconds 10 
                    }
                # check to see if the computer wakes up within 5 minutes
                }  until ((Test-Connection $computerName -Quiet -count 2) -or ($count -ge 12)) 
                if ($count -ge 12) {
                    $Stopwatch.Stop()
                    $timer = $StopWatch.Elapsed.ToString('hh\:mm\:ss')
                    @{
                        'Computer Name'  = $computerName
                        'Error'          = 'Did not respond to WOL'
                        'Execution Time' = $timer
                    }
                # if the computer woke up, reboot it
                } else {
                    try {
                        $osVersion = Invoke-Command $computerName -ScriptBlock {Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption}
                        if ($osVersion -notlike '*Server*') {
                            New-RemoteCheckpoint -Computer $computerName $timer
                        }
                        Invoke-RemoteRestart $computerName $jobStartTime $stopWatch
                    } catch {
                        $Stopwatch.Stop()
                        $timer = $StopWatch.Elapsed.ToString('hh\:mm\:ss')
                        @{
                            'Computer Name'  = $computerName
                            'Error'          = 'Did not reboot'
                            'Execution Time' = $timer
                        }
                    }
                } 
            # if the wake on lan function failed, log it
            } catch {
                $Stopwatch.Stop()
                $timer = $StopWatch.Elapsed.ToString('hh\:mm\:ss')
                @{
                    'Computer Name'  = $computerName
                    'Error'          = 'Failed to send WOL Packet'
                    'Execution Time' = $timer
                }
            }
        }
    }
} # end function restartJob

<#
        #####################################################################################
        ################################  Start of script  ##################################
        #####################################################################################
#>

if (Test-Path $logFilePath) {
    Remove-Item $logFilePath
}

$computersToReboot | Foreach-Object {
    $computerName = $_
    $clientMAC = $computerMacAddresses | Where-Object {$_.Host.split('.')[0] -eq $computerName}
    Invoke-RestartJob $computerName $clientMAC
}
Wait-Job -Name $computersToReboot
$resultsRaw = Receive-Job -Name $computersToReboot -Keep
Remove-Job  -Name $computersToReboot

$results = Foreach ($computerName in $computersToReboot) {
    $jobResults = $resultsRaw | ForEach-Object {[pscustomobject]$_ | Where-Object {$_.'Computer Name' -like $computerName}}
    if ($jobResults -eq $null) { continue }
    [ordered] @{
        'Computer Name'  = $( $jobResults.'Computer Name'  )
        'Job Error'      = $( $jobResults.'Error'          )
        'Execution Time' = $( $jobResults.'Execution Time' )
    }
}

if ( -not [string]::IsNullOrEmpty($results) ) {
    $results.foreach({[pscustomobject]$_ }) | Out-File -FilePath $logFilePath -Force
    #PS Version 4 compatibility.  If there is only 1 computer then we re-create $computersToReport as an array of 1 hash table
    if ($results.gettype().name -eq 'OrderedDictionary'){
    $computersToReport = @($computersToReport)
    }
    # Send the sorted info for all computers that failed any status checks to New-HTMLReport to convert the info into an HTML table end email the table
    $emailBody = $results.foreach({[pscustomobject]$_ }) | 
        Sort-Object -Property 'Computer Name' | 
            New-HTMLReport
    $emailParameters = @{
        To         = $recipient
        From       = $sender
        Subject    = $subject
        Body       = $emailBody
        SmtpServer = $smtpServer
        BodyAsHtml = $true
        Credential = $credential
        Port       = $port
        UseSsl     = $true
    }
    Send-MailMessage @emailParameters
}