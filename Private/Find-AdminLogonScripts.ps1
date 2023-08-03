function Find-AdminLogonScripts {
    # Write-Verbose -Message "Checking for admins who have logon scripts set.."
    
    # Enabled user accounts
    $ldapFilter = "(&(objectCategory=User)(objectClass=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

    # Admin groups to match on
    $AdminGroups = "Account Operators|Administrators|Backup Operators|Cryptographic Operators|Distributed COM Users|Domain Admins|Domain Controllers|Enterprise Admins|Print Operators|Schema Admins|Server Operators"

    # Create a new ADSI searcher object
    $searcher = [adsisearcher]$ldapFilter

    # Specify the properties to retrieve
    $searcher.PropertiesToLoad.Add("samaccountname") | out-null
    $searcher.PropertiesToLoad.Add("scriptPath") | out-null

    # Execute the search
    $results = $searcher.FindAll()

    # Filter the results based on scriptPath and memberOf properties
    $AdminLogonScripts = $results | Where-Object { $_.Properties["scriptPath"] -ne $null -and ($adminGroups -match $AdminGroups) }

    # "`n[!] Admins found with logon scripts"
    $AdminLogonScripts | Foreach-object {
        $Results = [ordered] @{
            Type = 'AdminLogonScript'
            User = $_.Path
            LogonScript = $($_.Properties.scriptpath)
        }
        [pscustomobject] $Results
    }
}