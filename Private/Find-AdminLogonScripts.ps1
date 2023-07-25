function Find-AdminLogonScripts {
    $AdminGroups = "Domain Admins|Enterprise Admins|Administrators"
    # $AdminLogonScripts = Get-ADUser -Filter {Enabled -eq $true} -Properties samaccountname,scriptPath,memberOf | Where-Object {$null -ne $_.scriptPath -and $_.MemberOf -match $AdminGroups}
    
    # Enabled user accounts
    $ldapFilter = "(&(objectCategory=User)(objectClass=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

    # Admin groups to match on
    $AdminGroups = "Domain Admins|Enterprise Admins|Administrators"

    # Create a new ADSI searcher object
    $searcher = [adsisearcher]$ldapFilter

    # Specify the properties to retrieve
    $searcher.PropertiesToLoad.Add("samaccountname") | out-null
    $searcher.PropertiesToLoad.Add("scriptPath") | out-null

    # Execute the search
    $results = $searcher.FindAll()

    # Filter the results based on scriptPath and memberOf properties
    $AdminLogonScripts = $results | Where-Object { $_.Properties["scriptPath"] -ne $null -and ($adminGroups -match $AdminGroups) }

     "`n[!] Admins found with logon scripts"
    $AdminLogonScripts | Foreach-object {
        "- User: $($_.Path)"
        "- logonscript: $($_.Properties.scriptpath)"
        ""    
    }   
}