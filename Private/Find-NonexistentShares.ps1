function Find-NonexistentShares {
    [CmdletBinding()]
    param (
        [array]$LogonScripts
    )
    
    
    $LogonScriptShares = @()
    [Array] $LogonScriptShares = foreach ($script in $LogonScripts) {
        $temp = Get-Content $script.FullName | Select-String -Pattern '.*net use.*','New-SmbMapping','.MapNetworkDrive' | ForEach-Object { $_.Matches.Value } 
        $temp = $temp | Select-String -Pattern '\\\\[\w\.\-]+\\[\w\-_\\.]+' | ForEach-Object { $_.Matches.Value }
        $temp | ForEach-Object {
            $ServerList = [ordered] @{
                Server = $_ -split '\\' | Where-Object {$_ -ne ""} | Select-Object -First 1
                Share = $_
                Script = $Script.FullName
            }
            [pscustomobject] $ServerList
            # Write-Host "$($ServerList.Share)"
        }
    }

    $LogonScriptShares = $LogonScriptShares | Sort-Object -Property Server -Unique
    # $LogonScriptShares | ForEach-Object { Write-Host "$($_.Share)"}

    $NonExistentShares = @()
    [Array] $NonExistentShares = foreach ($LogonScriptShare in $LogonScriptShares) {
        Write-Host "Checking $($LogonScriptShare.Server)"
        try { 
            $DNSEntry = [System.Net.DNS]::GetHostByName($LogonScriptShare.Server)
        } catch {
            $ServerWithoutDNS = $LogonScriptShare
        }
        if ($ServerWithoutDNS) {
            write-host "$($ServerWithoutDNS.Server)"
            $Results = [ordered] @{
                Type = 'NonexistentShare'
                Server = $ServerWithoutDNS.Server
                Share = $ServerWithoutDNS.Share
                Script = $ServerWithoutDNS.Script
                DNS = 'No'
            }
        }
        [pscustomobject] $Results
    }

    $NonExistentShares | Sort-Object -Property Server -Unique
}
