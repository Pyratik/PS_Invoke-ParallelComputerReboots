#Get-DHCPClient was adapted from JeremyEngelWork's code 
#http://gallery.technet.microsoft.com/scriptcenter/05b1d766-25a6-45cd-a0f1-8741ff6c04ec 
#Get-DHCPClient -server DHCP-Server.local.domain.com -scope 10.0.0.0 -broadcast 255.255.255.255 | Export-Csv -path c:\scripts\DHCP_Clients.csv
function Get-DHCPClient {  
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][PSObject]$Server,  
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][PSObject]$Scope, 
        [bool]$local=$true, 
        [string]$Broadcast 
    )
  
    $reservations = @()  
  
    if ($local) { 
        Write-Host "Getting DHCP leases on local server" 
        $text = netsh dhcp server \\ scope $Scope show clients 
    } else { 
        Write-Host "Getting DHCP leases on remote server $server" 
        try {
            $text = Invoke-Command -computer $Server {netsh dhcp server \\$using:Server scope $using:Scope show clients} -ErrorAction Stop 
        } catch { 
            Write-Error "FAIL: Are you sure that WinRM is enabled on the remote server????  http://support.microsoft.com/kb/555966" 
            break 
        } 
    } 
    $result = if ( $text.GetType() -eq [string] ) {
        $text
    } else {
        $text[($text.Count-1)]
    }    
    if ( $result.Contains("The command needs a valid Scope IP Address") ) { 
        Write-Host "ERROR: $Scope is not a valid scope on $Server." -ForeGroundColor Red
        return 
    }
    if ( $result.Contains("Server may not function properly") ) {
        Write-Host "ERROR: $Server is inaccessible or is not a DHCP server." -ForeGroundColor Red
        return
    }
    if ( $result.Contains("The following command was not found") ) {
        Write-Host "This command must be run on a local or remote DHCP server"
        return 
    }
    for ( $i=8; $i -lt $text.Count; $i++) {  
        if ( -not $text[$i]) {
            break
        }  
        $parts = $text[$i].Split("-") | Foreach-Object { $_.Trim() }  
        if ( $IPAddress -and $parts[0] -ne $IPAddress ) { 
            continue 
        }
        $reservation            = New-Object DHCPClient  
        $reservation.IPAddress  = $parts[0]  
        $reservation.MACAddress = [string]::Join("-",$parts[2..7])   
        $reservation.Host       = Get-Hostname($reservation.IPAddress) 
        $reservation.Broadcast  = $Broadcast 
        $reservation.Server     = $Server 
        $reservations          += $reservation      
    }  
    return $reservations
}  

$make_struct = @" 
public struct DHCPClient {  
public string Host; 
public string IPAddress;  
public string MACAddress; 
public string Broadcast; 
public string Server; 
public override string ToString() { return IPAddress; }  
}  
"@ 
Add-Type -TypeDefinition $make_struct

function Get-Hostname { 
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][PSObject]$IPAddress
    ) 
    $ErrorActionPreference = "SilentlyContinue" 
    $result = [net.dns]::GetHostEntry($IPAddress) 
    if ( -not $result.Hostname ) {
        return "Unresolvable"
    } else {
        return $result.Hostname
    }
}