function Get-DomainAdmins {
    [CmdletBinding()]
    param()

    # $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $Domains = Get-Domains
    
    foreach ($Domain in $Domains) {
        $DomainController = $Domain.PdcRoleOwner
        $adsiPath = "LDAP://$($DomainController.Name)/DC=$($Domain.Name -replace '\.', ',DC=')"
        
        $root = New-Object System.DirectoryServices.DirectoryEntry($adsiPath)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
        $searcher.Filter = "(&(objectCategory=group)(cn=Domain Admins))"

        # Specify the property to retrieve (samaccountname of members)
        $searcher.PropertiesToLoad.Add("member") | out-null

        # Execute the search
        $result = $searcher.FindOne()

        $DomainAdmins = @()
        $members = $result.Properties["member"]
        foreach ($member in $members) {
            $user = [adsi]"LDAP://$member"
            $DomainAdmins += $user.sAMAccountName
        }

        $DomainAdmins
    }
}