function Get-DomainAdmins {
    [CmdletBinding()]
    param()

    $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

    # Set the distinguished name of the "Domain Admins" group (update this with the correct DN)
    $domainAdminsGroupDN = "CN=Domain Admins,CN=Users,DC=$($($currentDomain.Name).split('.')[0]),DC=$($($currentDomain.Name).split('.')[1])"

    # Create a new ADSI searcher object for the "Domain Admins" group
    $searcher = [adsisearcher]"(distinguishedName=$domainAdminsGroupDN)"

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

    return $DomainAdmins
}