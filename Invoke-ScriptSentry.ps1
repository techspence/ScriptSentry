function Invoke-ScriptSentry{
<#
.SYNOPSIS
ScriptSentry finds misconfigured and dangerous logon scripts.

.DESCRIPTION
ScriptSentry searches the NETLOGON share & Group Policy to 
    1) identify plaintext credentials in logon scripts
    2) identify admins that have logon script set 
    3) identify scripts and shares that may have dangerous permissions

.EXAMPLE
Invoke-ScriptSentry

.EXAMPLE
Invoke-ScriptSentry | Out-File c:\temp\ScriptSentry.txt

.EXAMPLE
Invoke-ScriptSentry -SaveOutput $true

#>
[CmdletBinding()]
Param(
    [boolean]$SaveOutput = $false
)
    
function Get-ForestDomains {
    [CmdletBinding()]
    param()

    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $forest.Domains
}
function Get-Domain {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose '[Get-Domain] Using alternate credentials for Get-Domain'

            if ($PSBoundParameters['Domain']) {
                $TargetDomain = $Domain
            }
            else {
                # if no domain is supplied, extract the logon domain from the PSCredential passed
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-Domain] Extracted domain '$TargetDomain' from -Credential"
            }

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[Get-Domain] Error retrieving the current domain: $_"
            }
        }
    }
}
function Get-DomainSearcher {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBasePrefix,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $TargetDomain = $Domain

            if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                # see if we can grab the user DNS logon domain from environment variables
                $UserDomain = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $UserDomain) {
                    $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$UserDomain"
                }
            }
        }
        elseif ($PSBoundParameters['Credential']) {
            # if not -Domain is specified, but -Credential is, try to retrieve the current domain name with Get-Domain
            $DomainObject = Get-Domain -Credential $Credential
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
            # see if we can grab the user DNS logon domain from environment variables
            $TargetDomain = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $TargetDomain) {
                $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomain"
            }
        }
        else {
            # otherwise, resort to Get-Domain to retrieve the current domain object
            write-verbose "get-domain"
            $DomainObject = Get-Domain
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }

        if ($PSBoundParameters['Server']) {
            # if there's not a specified server to bind to, try to pull a logon server from ENV variables
            $BindServer = $Server
        }

        $SearchString = 'LDAP://'

        if ($BindServer -and ($BindServer.Trim() -ne '')) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += '/'
            }
        }

        if ($PSBoundParameters['SearchBasePrefix']) {
            $SearchString += $SearchBasePrefix + ','
        }

        if ($PSBoundParameters['SearchBase']) {
            if ($SearchBase -Match '^GC://') {
                # if we're searching the global catalog, get the path in the right format
                $DN = $SearchBase.ToUpper().Trim('/')
                $SearchString = ''
            }
            else {
                if ($SearchBase -match '^LDAP://') {
                    if ($SearchBase -match "LDAP://.+/.+") {
                        $SearchString = ''
                        $DN = $SearchBase
                    }
                    else {
                        $DN = $SearchBase.SubString(7)
                    }
                }
                else {
                    $DN = $SearchBase
                }
            }
        }
        else {
            # transform the target domain name into a distinguishedName if an ADS search base is not specified
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $DN = "DC=$($TargetDomain.Replace('.', ',DC='))"
            }
        }

        $SearchString += $DN
        Write-Verbose "[Get-DomainSearcher] search base: $SearchString"

        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[Get-DomainSearcher] Using alternate credentials for LDAP connection"
            # bind to the inital search object using alternate credentials
            $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            # bind to the inital object using the current credentials
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }

        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False
        $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($PSBoundParameters['ServerTimeLimit']) {
            $Searcher.ServerTimeLimit = $ServerTimeLimit
        }

        if ($PSBoundParameters['Tombstone']) {
            $Searcher.Tombstone = $True
        }

        if ($PSBoundParameters['LDAPFilter']) {
            $Searcher.filter = $LDAPFilter
        }

        if ($PSBoundParameters['SecurityMasks']) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($PSBoundParameters['Properties']) {
            # handle an array of properties to load w/ the possibility of comma-separated strings
            $PropertiesToLoad = $Properties| ForEach-Object { $_.Split(',') }
            $Null = $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }

        $Searcher
    }
}
function Get-DomainGroupMember {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('StrongView.GroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(ParameterSetName = 'ManualRecurse')]
        [Switch]
        $Recurse,

        [Parameter(ParameterSetName = 'RecurseUsingMatchingRule')]
        [Switch]
        $RecurseUsingMatchingRule,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{
            'Properties' = 'member,samaccountname,distinguishedname'
        }
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }

        $ADNameArguments = @{}
        if ($PSBoundParameters['Domain']) { $ADNameArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $ADNameArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $ADNameArguments['Credential'] = $Credential }
    }

    PROCESS {
        $GroupSearcher = Get-DomainSearcher @SearcherArguments
        if ($GroupSearcher) {
            if ($PSBoundParameters['RecurseUsingMatchingRule']) {
                $SearcherArguments['Identity'] = $Identity
                $SearcherArguments['Raw'] = $True
                $Group = Get-DomainGroup @SearcherArguments

                if (-not $Group) {
                    Write-Warning "[Get-DomainGroupMember] Error searching for group with identity: $Identity"
                }
                else {
                    $GroupFoundName = $Group.properties.item('samaccountname')[0]
                    $GroupFoundDN = $Group.properties.item('distinguishedname')[0]

                    if ($PSBoundParameters['Domain']) {
                        $GroupFoundDomain = $Domain
                    }
                    else {
                        # if a domain isn't passed, try to extract it from the found group distinguished name
                        if ($GroupFoundDN) {
                            $GroupFoundDomain = $GroupFoundDN.SubString($GroupFoundDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    Write-Verbose "[Get-DomainGroupMember] Using LDAP matching rule to recurse on '$GroupFoundDN', only user accounts will be returned."
                    $GroupSearcher.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$GroupFoundDN))"
                    $GroupSearcher.PropertiesToLoad.AddRange(('distinguishedName'))
                    $Members = $GroupSearcher.FindAll() | ForEach-Object {$_.Properties.distinguishedname[0]}
                }
                $Null = $SearcherArguments.Remove('Raw')
            }
            else {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($IdentityInstance -match '^S-1-') {
                        $IdentityFilter += "(objectsid=$IdentityInstance)"
                    }
                    elseif ($IdentityInstance -match '^CN=') {
                        $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                            # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                            #   and rebuild the domain searcher
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-DomainGroupMember] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            $SearcherArguments['Domain'] = $IdentityDomain
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not $GroupSearcher) {
                                Write-Warning "[Get-DomainGroupMember] Unable to retrieve domain searcher for '$IdentityDomain'"
                            }
                        }
                    }
                    elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    elseif ($IdentityInstance.Contains('\')) {
                        $ConvertedIdentityInstance = $IdentityInstance.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                        if ($ConvertedIdentityInstance) {
                            $GroupDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                            $GroupName = $IdentityInstance.Split('\')[1]
                            $IdentityFilter += "(samAccountName=$GroupName)"
                            $SearcherArguments['Domain'] = $GroupDomain
                            Write-Verbose "[Get-DomainGroupMember] Extracted domain '$GroupDomain' from '$IdentityInstance'"
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        $IdentityFilter += "(samAccountName=$IdentityInstance)"
                    }
                }

                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }

                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[Get-DomainGroupMember] Using additional LDAP filter: $LDAPFilter"
                    $Filter += "$LDAPFilter"
                }

                $GroupSearcher.filter = "(&(objectCategory=group)$Filter)"
                Write-Verbose "[Get-DomainGroupMember] Get-DomainGroupMember filter string: $($GroupSearcher.filter)"
                try {
                    $Result = $GroupSearcher.FindOne()
                }
                catch {
                    Write-Warning "[Get-DomainGroupMember] Error searching for group with identity '$Identity': $_"
                    $Members = @()
                }

                $GroupFoundName = ''
                $GroupFoundDN = ''

                if ($Result) {
                    $Members = $Result.properties.item('member')

                    if ($Members.count -eq 0) {
                        # ranged searching, thanks @meatballs__ !
                        $Finished = $False
                        $Bottom = 0
                        $Top = 0

                        while (-not $Finished) {
                            $Top = $Bottom + 1499
                            $MemberRange="member;range=$Bottom-$Top"
                            $Bottom += 1500
                            $Null = $GroupSearcher.PropertiesToLoad.Clear()
                            $Null = $GroupSearcher.PropertiesToLoad.Add("$MemberRange")
                            $Null = $GroupSearcher.PropertiesToLoad.Add('samaccountname')
                            $Null = $GroupSearcher.PropertiesToLoad.Add('distinguishedname')

                            try {
                                $Result = $GroupSearcher.FindOne()
                                $RangedProperty = $Result.Properties.PropertyNames -like "member;range=*"
                                $Members += $Result.Properties.item($RangedProperty)
                                $GroupFoundName = $Result.properties.item('samaccountname')[0]
                                $GroupFoundDN = $Result.properties.item('distinguishedname')[0]

                                if ($Members.count -eq 0) {
                                    $Finished = $True
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                $Finished = $True
                            }
                        }
                    }
                    else {
                        $GroupFoundName = $Result.properties.item('samaccountname')[0]
                        $GroupFoundDN = $Result.properties.item('distinguishedname')[0]
                        $Members += $Result.Properties.item($RangedProperty)
                    }

                    if ($PSBoundParameters['Domain']) {
                        $GroupFoundDomain = $Domain
                    }
                    else {
                        # if a domain isn't passed, try to extract it from the found group distinguished name
                        if ($GroupFoundDN) {
                            $GroupFoundDomain = $GroupFoundDN.SubString($GroupFoundDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                }
            }

            ForEach ($Member in $Members) {
                if ($Recurse -and $UseMatchingRule) {
                    $Properties = $_.Properties
                }
                else {
                    $ObjectSearcherArguments = $SearcherArguments.Clone()
                    $ObjectSearcherArguments['Identity'] = $Member
                    $ObjectSearcherArguments['Raw'] = $True
                    $ObjectSearcherArguments['Properties'] = 'distinguishedname,cn,samaccountname,objectsid,objectclass'
                    $Object = Get-DomainObject @ObjectSearcherArguments
                    $Properties = $Object.Properties
                }

                if ($Properties) {
                    $GroupMember = New-Object PSObject
                    $GroupMember | Add-Member Noteproperty 'GroupDomain' $GroupFoundDomain
                    $GroupMember | Add-Member Noteproperty 'GroupName' $GroupFoundName
                    $GroupMember | Add-Member Noteproperty 'GroupDistinguishedName' $GroupFoundDN

                    if ($Properties.objectsid) {
                        $MemberSID = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectsid[0], 0).Value)
                    }
                    else {
                        $MemberSID = $Null
                    }

                    try {
                        $MemberDN = $Properties.distinguishedname[0]
                        if ($MemberDN -match 'ForeignSecurityPrincipals|S-1-5-21') {
                            try {
                                if (-not $MemberSID) {
                                    $MemberSID = $Properties.cn[0]
                                }
                                $MemberSimpleName = Convert-ADName -Identity $MemberSID -OutputType 'DomainSimple' @ADNameArguments

                                if ($MemberSimpleName) {
                                    $MemberDomain = $MemberSimpleName.Split('@')[1]
                                }
                                else {
                                    Write-Warning "[Get-DomainGroupMember] Error converting $MemberDN"
                                    $MemberDomain = $Null
                                }
                            }
                            catch {
                                Write-Warning "[Get-DomainGroupMember] Error converting $MemberDN"
                                $MemberDomain = $Null
                            }
                        }
                        else {
                            # extract the FQDN from the Distinguished Name
                            $MemberDomain = $MemberDN.SubString($MemberDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    catch {
                        $MemberDN = $Null
                        $MemberDomain = $Null
                    }

                    if ($Properties.samaccountname) {
                        # forest users have the samAccountName set
                        $MemberName = $Properties.samaccountname[0]
                    }
                    else {
                        # external trust users have a SID, so convert it
                        try {
                            $MemberName = ConvertFrom-SID -ObjectSID $Properties.cn[0] @ADNameArguments
                        }
                        catch {
                            # if there's a problem contacting the domain to resolve the SID
                            $MemberName = $Properties.cn[0]
                        }
                    }

                    if ($Properties.objectclass -match 'computer') {
                        $MemberObjectClass = 'computer'
                    }
                    elseif ($Properties.objectclass -match 'group') {
                        $MemberObjectClass = 'group'
                    }
                    elseif ($Properties.objectclass -match 'user') {
                        $MemberObjectClass = 'user'
                    }
                    else {
                        $MemberObjectClass = $Null
                    }
                    $GroupMember | Add-Member Noteproperty 'MemberDomain' $MemberDomain
                    $GroupMember | Add-Member Noteproperty 'MemberName' $MemberName
                    $GroupMember | Add-Member Noteproperty 'MemberDistinguishedName' $MemberDN
                    $GroupMember | Add-Member Noteproperty 'MemberObjectClass' $MemberObjectClass
                    $GroupMember | Add-Member Noteproperty 'MemberSID' $MemberSID
                    $GroupMember.PSObject.TypeNames.Insert(0, 'StrongView.GroupMember')
                    $GroupMember

                    # if we're doing manual recursion
                    if ($PSBoundParameters['Recurse'] -and $MemberDN -and ($MemberObjectClass -match 'group')) {
                        Write-Verbose "[Get-DomainGroupMember] Manually recursing on group: $MemberDN"
                        $SearcherArguments['Identity'] = $MemberDN
                        $Null = $SearcherArguments.Remove('Properties')
                        Get-DomainGroupMember @SearcherArguments
                    }
                }
            }
            $GroupSearcher.dispose()
        }
    }
}
function Get-DomainUser {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('StrongView.User')]
    [OutputType('StrongView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
            [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
            [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
            [String[]]
            $Identity,
    
            [Switch]
            $SPN,
    
            [Switch]
            $AdminCount,
    
            [Parameter(ParameterSetName = 'AllowDelegation')]
            [Switch]
            $AllowDelegation,
    
            [Parameter(ParameterSetName = 'DisallowDelegation')]
            [Switch]
            $DisallowDelegation,
    
            [Switch]
            $TrustedToAuth,
    
            [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
            [Switch]
            $PreauthNotRequired,
    
            [ValidateNotNullOrEmpty()]
            [String]
            $Domain,
    
            [ValidateNotNullOrEmpty()]
            [Alias('Filter')]
            [String]
            $LDAPFilter,
    
            [ValidateNotNullOrEmpty()]
            [String[]]
            $Properties,
    
            [ValidateNotNullOrEmpty()]
            [Alias('ADSPath')]
            [String]
            $SearchBase,
    
            [ValidateNotNullOrEmpty()]
            [Alias('DomainController')]
            [String]
            $Server,
    
            [ValidateSet('Base', 'OneLevel', 'Subtree')]
            [String]
            $SearchScope = 'Subtree',
    
            [ValidateRange(1, 10000)]
            [Int]
            $ResultPageSize = 200,
    
            [ValidateRange(1, 10000)]
            [Int]
            $ServerTimeLimit,
    
            [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
            [String]
            $SecurityMasks,
    
            [Switch]
            $Tombstone,
    
            [Alias('ReturnOne')]
            [Switch]
            $FindOne,
    
            [Management.Automation.PSCredential]
            [Management.Automation.CredentialAttribute()]
            $Credential = [Management.Automation.PSCredential]::Empty,
    
            [Switch]
            $Raw
        )
    BEGIN {
            $SearcherArguments = @{}
            if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
            if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
            if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
            if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
            if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
            if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
            if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
            if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
            if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
            if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
            $UserSearcher = Get-DomainSearcher @SearcherArguments
        }
    
    PROCESS {
            if ($UserSearcher) {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($IdentityInstance -match '^S-1-') {
                        $IdentityFilter += "(objectsid=$IdentityInstance)"
                    }
                    elseif ($IdentityInstance -match '^CN=') {
                        $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                            # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                            #   and rebuild the domain searcher
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-DomainUser] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            $SearcherArguments['Domain'] = $IdentityDomain
                            $UserSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not $UserSearcher) {
                                Write-Warning "[Get-DomainUser] Unable to retrieve domain searcher for '$IdentityDomain'"
                            }
                        }
                    }
                    elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    elseif ($IdentityInstance.Contains('\')) {
                        $ConvertedIdentityInstance = $IdentityInstance.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                        if ($ConvertedIdentityInstance) {
                            $UserDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                            $UserName = $IdentityInstance.Split('\')[1]
                            $IdentityFilter += "(samAccountName=$UserName)"
                            $SearcherArguments['Domain'] = $UserDomain
                            Write-Verbose "[Get-DomainUser] Extracted domain '$UserDomain' from '$IdentityInstance'"
                            $UserSearcher = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        $IdentityFilter += "(samAccountName=$IdentityInstance)"
                    }
                }
    
                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }
    
                if ($PSBoundParameters['SPN']) {
                    Write-Verbose '[Get-DomainUser] Searching for non-null service principal names'
                    $Filter += '(servicePrincipalName=*)'
                }
                if ($PSBoundParameters['AllowDelegation']) {
                    Write-Verbose '[Get-DomainUser] Searching for users who can be delegated'
                    # negation of "Accounts that are sensitive and not trusted for delegation"
                    $Filter += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
                }
                if ($PSBoundParameters['DisallowDelegation']) {
                    Write-Verbose '[Get-DomainUser] Searching for users who are sensitive and not trusted for delegation'
                    $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
                }
                if ($PSBoundParameters['AdminCount']) {
                    Write-Verbose '[Get-DomainUser] Searching for adminCount=1'
                    $Filter += '(admincount=1)'
                }
                if ($PSBoundParameters['TrustedToAuth']) {
                    Write-Verbose '[Get-DomainUser] Searching for users that are trusted to authenticate for other principals'
                    $Filter += '(msds-allowedtodelegateto=*)'
                }
                if ($PSBoundParameters['PreauthNotRequired']) {
                    Write-Verbose '[Get-DomainUser] Searching for user accounts that do not require kerberos preauthenticate'
                    $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
                }
                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[Get-DomainUser] Using additional LDAP filter: $LDAPFilter"
                    $Filter += "$LDAPFilter"
                }
    
                # build the LDAP filter for the dynamic UAC filter value
                $UACFilter | Where-Object {$_} | ForEach-Object {
                    if ($_ -match 'NOT_.*') {
                        $UACField = $_.Substring(4)
                        $UACValue = [Int]($UACEnum::$UACField)
                        $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                    }
                    else {
                        $UACValue = [Int]($UACEnum::$_)
                        $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                    }
                }
    
                $UserSearcher.filter = "(&(samAccountType=805306368)$Filter)"
                Write-Verbose "[Get-DomainUser] filter string: $($UserSearcher.filter)"
    
                if ($PSBoundParameters['FindOne']) { $Results = $UserSearcher.FindOne() }
                else { $Results = $UserSearcher.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters['Raw']) {
                        # return raw result objects
                        $User = $_
                        $User.PSObject.TypeNames.Insert(0, 'StrongView.User.Raw')
                    }
                    else {
                        $User = Convert-LDAPProperty -Properties $_.Properties
                        $User.PSObject.TypeNames.Insert(0, 'StrongView.User')
                    }
                    $User
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainUser] Error disposing of the Results object: $_"
                    }
                }
                $UserSearcher.dispose()
            }
        }
}
function Get-DomainObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('StrongView.ADObject')]
    [OutputType('StrongView.ADObject.Raw')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($ObjectSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^(CN|OU|DC)=') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainObject] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $ObjectSearcher) {
                            Write-Warning "[Get-DomainObject] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('\')) {
                    $ConvertedIdentityInstance = $IdentityInstance.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($ConvertedIdentityInstance) {
                        $ObjectDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                        $ObjectName = $IdentityInstance.Split('\')[1]
                        $IdentityFilter += "(samAccountName=$ObjectName)"
                        $SearcherArguments['Domain'] = $ObjectDomain
                        Write-Verbose "[Get-DomainObject] Extracted domain '$ObjectDomain' from '$IdentityInstance'"
                        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
                    }
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                else {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(displayname=$IdentityInstance))"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainObject] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            # build the LDAP filter for the dynamic UAC filter value
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            if ($Filter -and $Filter -ne '') {
                $ObjectSearcher.filter = "(&$Filter)"
            }
            Write-Verbose "[Get-DomainObject] Get-DomainObject filter string: $($ObjectSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $ObjectSearcher.FindOne() }
            else { $Results = $ObjectSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    # return raw result objects
                    $Object = $_
                    $Object.PSObject.TypeNames.Insert(0, 'StrongView.ADObject.Raw')
                }
                else {
                    $Object = Convert-LDAPProperty -Properties $_.Properties
                    $Object.PSObject.TypeNames.Insert(0, 'StrongView.ADObject')
                }
                $Object
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainObject] Error disposing of the Results object: $_"
                }
            }
            $ObjectSearcher.dispose()
        }
    }
}
function Get-LogonScripts {
    [CmdletBinding()]
    param()

    # Get the current domain name from the environment
    # $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $Domains = Get-ForestDomains

    foreach ($Domain in $Domains) {
        # $SysvolScripts = '\\' + (Get-ADDomain).DNSRoot + '\sysvol\' + (Get-ADDomain).DNSRoot + '\scripts'
        $SysvolScripts = "\\$($Domain.Name)\sysvol\$($Domain.Name)\scripts"
        $ExtensionList = '.bat|.vbs|.ps1|.cmd|.kix'
        $LogonScripts = try { Get-ChildItem -Path $SysvolScripts -Recurse | Where-Object {$_.Extension -match $ExtensionList} } catch {}
        Write-Verbose "[+] Logon scripts:"
        $LogonScripts | ForEach-Object {
            Write-Verbose -Message "$($_.fullName)"
        }
        $LogonScripts | Sort-Object -Unique
    }
}
function Get-GPOLogonScripts {
    [CmdletBinding()]
    param()

    # Get the current domain name from the environment
    # $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $Domains = Get-ForestDomains

    foreach ($Domain in $Domains) {
        $Policies = Get-ChildItem "\\$($Domain.Name)\SysVol\$($Domain.Name)\Policies" -ErrorAction SilentlyContinue
        $Policies | ForEach-Object { 
            $GPOLogonScripts = Get-Content -Path "$($_.FullName)\User\Scripts\scripts.ini" -ErrorAction SilentlyContinue | Select-String -Pattern "\\\\.*\.\w+" | ForEach-Object { $_.Matches.Value }
            Write-Verbose "[+] GPO Logon scripts:"
            $GPOLogonScripts | ForEach-Object {
                Write-Verbose -Message "$($_.fullName)"
            }
            if ($GPOLogonScripts) {
                Get-Item -Path $GPOLogonScripts | Sort-Object -Unique
            }
        }
    }
}
function Get-NetlogonSysvol {
    [CmdletBinding()]
    param()

    $Domains = Get-ForestDomains
    foreach ($Domain in $Domains){
        "\\$($Domain.Name)\NETLOGON"
        "\\$($Domain.Name)\SYSVOL"
    }
}
function Get-Art($Version) {
"
 _______  _______  _______ _________ _______ _________ _______  _______  _       _________ _______          
(  ____ \(  ____ \(  ____ )\__   __/(  ____ )\__   __/(  ____ \(  ____ \( (    /|\__   __/(  ____ )|\     /|
| (    \/| (    \/| (    )|   ) (   | (    )|   ) (   | (    \/| (    \/|  \  ( |   ) (   | (    )|( \   / )
| (_____ | |      | (____)|   | |   | (____)|   | |   | (_____ | (__    |   \ | |   | |   | (____)| \ (_) / 
(_____  )| |      |     __)   | |   |  _____)   | |   (_____  )|  __)   | (\ \) |   | |   |     __)  \   /  
      ) || |      | (\ (      | |   | (         | |         ) || (      | | \   |   | |   | (\ (      ) (   
/\____) || (____/\| ) \ \_____) (___| )         | |   /\____) || (____/\| )  \  |   | |   | ) \ \__   | |   
\_______)(_______/|/   \__/\_______/|/          )_(   \_______)(_______/|/    )_)   )_(   |/   \__/   \_/   
                              by: Spencer Alessi @techspence                                                                 
                                          v$Version                                           
                                      __,_______
                                     / __.==---/ * * * * * *
                                    / (-'
                                    `-'
                           Setting phasers to stun, please wait..
"
}
function Convert-LDAPProperty {
<#
.SYNOPSIS

Helper that converts specific LDAP property result fields and outputs
a custom psobject.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Converts a set of raw LDAP properties results from ADSI/LDAP searches
into a proper PSObject. Used by several of the Get-Domain* function.

.PARAMETER Properties

Properties object to extract out LDAP fields for display.

.OUTPUTS

System.Management.Automation.PSCustomObject

A custom PSObject with LDAP hashtable properties translated.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                # convert all listed sids (i.e. if multiple are listed in sidHistory)
                #$ObjectProperties[$_] = $Properties[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                #$ObjectProperties[$_] = $Properties[$_][0] -as $GroupTypeEnum
            }
            elseif ($_ -eq 'samaccounttype') {
                #$ObjectProperties[$_] = $Properties[$_][0] -as $SamAccountTypeEnum
            }
            elseif ($_ -eq 'objectguid') {
                # convert the GUID to a string
                #$ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                #$ObjectProperties[$_] = $Properties[$_][0] -as $UACEnum
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                # $ObjectProperties[$_] = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                if ($Descriptor.Owner) {
                    $ObjectProperties['Owner'] = $Descriptor.Owner
                }
                if ($Descriptor.Group) {
                    $ObjectProperties['Group'] = $Descriptor.Group
                }
                if ($Descriptor.DiscretionaryAcl) {
                    $ObjectProperties['DiscretionaryAcl'] = $Descriptor.DiscretionaryAcl
                }
                if ($Descriptor.SystemAcl) {
                    $ObjectProperties['SystemAcl'] = $Descriptor.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($Properties[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $ObjectProperties[$_] = "NEVER"
                }
                else {
                    $ObjectProperties[$_] = [datetime]::fromfiletime($Properties[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                # convert timestamps
                if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                    # if we have a System.__ComObject
                    $Temp = $Properties[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    # otherwise just a string
                    $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
                }
            }
            elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # try to convert misc com objects
                $Prop = $Properties[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[Convert-LDAPProperty] error: $_"
                    $ObjectProperties[$_] = $Prop[$_]
                }
            }
            elseif ($Properties[$_].count -eq 1) {
                $ObjectProperties[$_] = $Properties[$_][0]
            }
            else {
                $ObjectProperties[$_] = $Properties[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $ObjectProperties
    }
    catch {
        Write-Warning "[Convert-LDAPProperty] Error parsing LDAP properties : $_"
    }
}
function Find-AdminLogonScripts {
    [CmdletBinding()]
    param (
        [array]$AdminUsers
    ) 
    # Enabled user accounts
    Foreach ($Admin in $AdminUsers) {
        $AdminLogonScripts = Get-DomainUser -Identity $Admin.MemberName | Where-Object { $_.scriptPath -ne $null}
        
        # "`n[!] Admins found with logon scripts"
        $AdminLogonScripts | Foreach-object {
            $Results = [ordered] @{
                Type = 'AdminLogonScript'
                User = $_.distinguishedname
                LogonScript = $_.scriptpath
            }
            [pscustomobject] $Results
        }
    }
}
function Find-LogonScriptCredentials {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )
    foreach ($script in $LogonScripts) {
        # Write-Verbose -Message "Checking $($Script.FullName) for credentials.."
        $Credentials = Get-Content -Path $script.FullName -ErrorAction SilentlyContinue | Select-String -Pattern "/user:","-AsPlainText" -AllMatches
        if ($Credentials) {
            # "`n[!] CREDENTIALS FOUND!"
            $Credentials | ForEach-Object {
                $Results = [ordered] @{
                    Type = 'Credentials'
                    File = $script.FullName
                    Credential = $_
                }
                [pscustomobject] $Results | Sort-Object -Unique
            }
        }
    }
}
function Find-UNCScripts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )

    $ExcludedMatches = "copy|&|/command|%WINDIR%|-i|\*"
    $UNCFiles = @()
    [Array] $UNCFiles = foreach ($script in $LogonScripts) {
        $MatchingUNCFiles = Get-Content $script.FullName -ErrorAction SilentlyContinue | Select-String -Pattern '\\\\.*\.\w+' | ForEach-Object { $_.Matches.Value }
        $MatchingUNCFiles | Foreach-object {
            if ($_ -match $ExcludedMatches) {
                # don't collect
            } else {
                $_
            }
        }
    }
    Write-Verbose "[+] UNC scripts:"
    $UNCFiles | ForEach-Object {
        Write-Verbose -Message "$_"
    }
    
    $UNCFiles | Sort-Object -Unique
}
function Find-MappedDrives {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )

    $Shares = @()
    [Array] $Shares = foreach ($script in $LogonScripts) {
        $temp = Get-Content $script.FullName -ErrorAction SilentlyContinue | Select-String -Pattern '.*net use.*','New-SmbMapping','.MapNetworkDrive' | ForEach-Object { $_.Matches.Value } 
        $temp = $temp | Select-String -Pattern '\\\\[\w\.\-]+\\[\w\-_\\.]+' | ForEach-Object { $_.Matches.Value }
        $temp | ForEach-Object {
            try {
                $Path = "$_"
                # Live servers we have access to
                (Get-Item $Path -ErrorAction Stop).FullName
            } catch [System.UnauthorizedAccessException] {
                # Servers we either don't have access to or do not exist
                Write-Verbose "$_ : You do not have access to $Directory`n"
            }
            catch {
                Write-Verbose "An error occurred: $($_.Exception.Message)"
            }
        }
    }

    Write-Verbose "[+] Mapped drives:"
    $Shares | Sort-Object -Unique | ForEach-Object {
        Write-Verbose -Message "$_"
    }

    $Shares | Sort-Object -Unique
}
function Find-NonexistentShares {
    [CmdletBinding()]
    param (
        [array]$LogonScripts,
        [array]$AdminUsers
    )
    $LogonScriptShares = @()
    [Array] $LogonScriptShares = foreach ($script in $LogonScripts) {
        $temp = Get-Content $script.FullName -ErrorAction SilentlyContinue | Select-String -Pattern '.*net use.*','New-SmbMapping','.MapNetworkDrive' | ForEach-Object { $_.Matches.Value }
        $temp = $temp | Select-String -Pattern '\\\\[\w\.\-]+\\[\w\-_\\.]+' | ForEach-Object { $_.Matches.Value }
        $temp | ForEach-Object {
            $ServerList = [ordered] @{
                Server = $_ -split '\\' | Where-Object {$_ -ne ""} | Select-Object -First 1
                Share = $_
                Script = $Script.FullName
            }
            [pscustomobject] $ServerList
        }
    }

    $LogonScriptShares = $LogonScriptShares #| Sort-Object -Property Share -Unique
    $AdminLogonScripts = Find-AdminLogonScripts -AdminUsers $AdminUsers
    $Admins = 'No'
    $Exploitable = 'No'

    $NonExistentShares = @()
    [Array] $NonExistentShares = foreach ($LogonScriptShare in $LogonScriptShares) {
        try { 
            $DNSEntry = [System.Net.DNS]::GetHostByName($LogonScriptShare.Server)
        } catch {
            $ServerWithoutDNS = $LogonScriptShare
        }

        if ($ServerWithoutDNS) {
            foreach ($AdminScript in $AdminLogonScripts) {
                if ((Get-Item $ServerWithoutDNS.Script).Name -match $AdminScript.LogonScript){
                    $Admins = $AdminScript.User
                    $Exploitable = 'Yes'
                    $Results = [ordered] @{
                        Type = 'ExploitableLogonScript'
                        Server = $ServerWithoutDNS.Server
                        Share = $ServerWithoutDNS.Share
                        Script = $ServerWithoutDNS.Script
                        DNS = 'No'
                        Exploitable = $Exploitable
                        Admins = $Admins
                    }
                } else {
                    $Admins = 'No'
                    $Exploitable = 'Potentially'
                    $Results = [ordered] @{
                        Type = 'NonexistentShare'
                        Server = $ServerWithoutDNS.Server
                        Share = $ServerWithoutDNS.Share
                        Script = $ServerWithoutDNS.Script
                        DNS = 'No'
                        Exploitable = $Exploitable
                        Admins = $Admins
                    }
                }
                [pscustomobject] $Results
            }
        }
    }

    $NonExistentShares
}
function Find-UnsafeLogonScriptPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts,
        [Parameter(Mandatory = $true)]
        [array]$SafeUsersList
    )

    $UnsafeRights = 'FullControl|Modify|Write'
    $SafeUsers = $SafeUsersList
    foreach ($script in $LogonScripts){
        # Write-Verbose -Message "Checking $($script.FullName) for unsafe permissions.."
        $ACL = (Get-Acl $script.FullName -ErrorAction SilentlyContinue).Access
        foreach ($entry in $ACL) {
            if ($entry.FileSystemRights -match $UnsafeRights `
                -and $entry.AccessControlType -eq "Allow" `
                -and $entry.IdentityReference -notmatch $SafeUsers
                ){
                $Results = [ordered] @{
                    Type = 'UnsafeLogonScriptPermission'
                    File = $script.FullName
                    User = $entry.IdentityReference.Value
                    Rights = $entry.FileSystemRights
                }
                [pscustomobject] $Results | Sort-Object -Unique
            }
        }
    }
}
function Find-UnsafeUNCPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$UNCScripts,
        [Parameter(Mandatory = $true)]
        [array]$SafeUsersList
    )

    $UnsafeRights = 'FullControl|Modify|Write'
    $SafeUsers = $SafeUsersList
    foreach ($script in $UNCScripts){
        # "Checking $script for unsafe permissions.."
        $ACL = (Get-Acl $script -ErrorAction SilentlyContinue).Access
        foreach ($entry in $ACL) {
            if ($entry.FileSystemRights -match $UnsafeRights `
                -and $entry.AccessControlType -eq "Allow" `
                -and $entry.IdentityReference -notmatch $SafeUsers
                ){
                if ($script -match 'NETLOGON|SYSVOL') {
                    $Type = 'UnsafeNetlogonSysvol'
                    $Results = [ordered] @{
                        Type = $Type
                        Folder = $script
                        User = $entry.IdentityReference.Value
                        Rights = $entry.FileSystemRights
                    }
                    [pscustomobject] $Results | Sort-Object -Unique
                } elseif ($script -match '\.') {
                    $Type = 'UnsafeUNCFilePermission'
                    $Results = [ordered] @{
                        Type = $Type
                        File = $script
                        User = $entry.IdentityReference.Value
                        Rights = $entry.FileSystemRights
                    }
                    [pscustomobject] $Results | Sort-Object -Unique
                } else {
                    $Type = 'UnsafeUNCFolderPermission'
                    $Results = [ordered] @{
                        Type = $Type
                        Folder = $script
                        User = $entry.IdentityReference.Value
                        Rights = $entry.FileSystemRights
                    }
                    [pscustomobject] $Results | Sort-Object -Unique
                }
            }
        }
    }
}
function Find-UnsafeLogonScriptPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts,
        [Parameter(Mandatory = $true)]
        [array]$SafeUsersList
    )

    $UnsafeRights = 'FullControl|Modify|Write'
    $SafeUsers = $SafeUsersList
    foreach ($script in $LogonScripts){
        # Write-Verbose -Message "Checking $($script.FullName) for unsafe permissions.."
        $ACL = try { (Get-Acl $script.FullName -ErrorAction SilentlyContinue).Access } catch{}
        foreach ($entry in $ACL) {
            if ($entry.FileSystemRights -match $UnsafeRights `
                -and $entry.AccessControlType -eq "Allow" `
                -and $entry.IdentityReference -notmatch $SafeUsers
                ){
                $Results = [ordered] @{
                    Type = 'UnsafeLogonScriptPermission'
                    File = $script.FullName
                    User = $entry.IdentityReference.Value
                    Rights = $entry.FileSystemRights
                }
                [pscustomobject] $Results | Sort-Object -Unique
            }
        }
    }
}
function Find-UnsafeGPOLogonScriptPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$GPOLogonScripts,
        [Parameter(Mandatory = $true)]
        [array]$SafeUsersList
    )

    $UnsafeRights = 'FullControl|Modify|Write'
    $SafeUsers = $SafeUsersList
    foreach ($script in $GPOLogonScripts){
        # Write-Verbose -Message "Checking $($script.FullName) for unsafe permissions.."
        $ACL = (Get-Acl $script.FullName -ErrorAction SilentlyContinue).Access
        foreach ($entry in $ACL) {
            if ($entry.FileSystemRights -match $UnsafeRights `
                -and $entry.AccessControlType -eq "Allow" `
                -and $entry.IdentityReference -notmatch $SafeUsers
                ){
                $Results = [ordered] @{
                    Type = 'UnsafeGPOLogonScriptPermission'
                    File = $script.FullName
                    User = $entry.IdentityReference.Value
                    Rights = $entry.FileSystemRights
                }
                [pscustomobject] $Results | Sort-Object -Unique
            }
        }
    }
}

function Show-Results {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results
    )

    $IssueTable = @{
        Credentials                    = 'Plaintext credentials'
        NonexistentShare               = 'Nonexistent Shares'
        ExploitableLogonScript         = 'Admins with logonscripts mapped from nonexistent share'
        AdminLogonScript               = 'Admins with logonscripts'
        UnsafeNetlogonSysvol           = 'Unsafe NETLOGON/SYSVOL permissions'
        UnsafeUNCFilePermission        = 'Unsafe UNC file permissions'
        UnsafeUNCFolderPermission      = 'Unsafe UNC folder permissions'
        UnsafeLogonScriptPermission    = 'Unsafe logon script permissions'
        UnsafeGPOLogonScriptPermission = 'Unsafe GPO logon script permissions'
    }

    if ($null -ne $Results) {
        $UniqueResults = $Results.Type | Sort-Object -Unique
        Write-Host "########## $($IssueTable[$UniqueResults]) ##########"
        # $Results | Format-List
        $Results | Format-Table -Wrap
    }
}

Get-Art -Version '0.6'

$SafeUsers = 'NT AUTHORITY\\SYSTEM|Administrator|NT SERVICE\\TrustedInstaller|Domain Admins|Server Operators|Enterprise Admins|CREATOR OWNER'
$AdminGroups = @("Account Operators", "Administrators", "Backup Operators", "Cryptographic Operators", "Distributed COM Users", "Domain Admins", "Domain Controllers", "Enterprise Admins", "Print Operators", "Schema Admins", "Server Operators")
$AdminUsers = $AdminGroups | ForEach-Object { (Get-DomainGroupMember -Identity $_ -Recurse | Where-Object {$_.MemberObjectClass -eq 'user'})} | Sort-Object -Property MemberName -Unique
$AdminUsers | ForEach-Object { $SafeUsers = $SafeUsers + '|' + $_.MemberName }

# Get a list of all logon scripts
$LogonScripts = Get-LogonScripts

# Get a list of all GPO logon scripts
$GPOLogonScripts = Get-GPOLogonScripts

if ($LogonScripts) {
    # Find logon scripts (.bat, .vbs, .cmd, .ps1, .kix) that contain unc paths (e.g. \\srv01\fileshare1)
    $UNCScripts = Find-UNCScripts -LogonScripts $LogonScripts

    # Find mapped drives (e.g. \\srv01\fileshare1, \\srv02\fileshare2\accounting)
    $MappedDrives = Find-MappedDrives -LogonScripts $LogonScripts

    # Find nonexistent shares
    $NonExistentSharesScripts = Find-NonexistentShares -LogonScripts $LogonScripts -AdminUsers $AdminUsers
    $NonExistentShares = $NonExistentSharesScripts | Where-Object {$_.Exploitable -eq 'Potentially'} | Sort-Object -Property Share -Unique

    # Find unsafe permissions on logon scripts
    $UnsafeLogonScripts = Find-UnsafeLogonScriptPermissions -LogonScripts $LogonScripts -SafeUsersList $SafeUsers

    # Find credentials in logon scripts
    $Credentials = Find-LogonScriptCredentials -LogonScripts $LogonScripts
} else {
    Write-Host "[i] No logon scripts found!`n" -ForegroundColor Cyan
}

if ($NonExistentShares) {
    # Find Exploitable logon scripts
    $ExploitableLogonScripts = $NonExistentSharesScripts | Where-Object {$_.Exploitable -eq 'Yes'}
} else {
    Write-Host "[i] No non-existent shares found!`n" -ForegroundColor Cyan
}

if ($UNCScripts) {
    # Find unsafe permissions for unc files found in logon scripts
    $UnsafeUNCPermissions = Find-UnsafeUNCPermissions -UNCScripts $UNCScripts -SafeUsersList $SafeUsers
} else {
    Write-Host "[i] No UNC files found!`n" -ForegroundColor Cyan
}

if ($MappedDrives) {
    # Find unsafe permissions for unc paths found in logon scripts
    $UnsafeMappedDrives = Find-UnsafeUNCPermissions -UNCScripts $MappedDrives -SafeUsersList $SafeUsers
} else {
    Write-Host "[i] No mapped drives found!`n" -ForegroundColor Cyan
}

# Find unsafe NETLOGON & SYSVOL share permissions
$NetlogonSysvol = Get-NetlogonSysvol
$UnsafeNetlogonSysvol = Find-UnsafeUNCPermissions -UNCScripts $NetlogonSysvol -SafeUsersList $SafeUsers

if ($GPOLogonScripts) {
    # Find unsafe permissions on GPO logon scripts
    $UnsafeGPOLogonScripts = Find-UnsafeGPOLogonScriptPermissions -GPOLogonScripts $GPOLogonScripts -SafeUsersList $SafeUsers
} else {
    Write-Host "[i] No GPO logon scripts found!`n" -ForegroundColor Cyan
}

# Find admins that have logon scripts assigned
$AdminLogonScripts = Find-AdminLogonScripts -AdminUsers $AdminUsers

# Show all results
if ($UnsafeMappedDrives) {Show-Results $UnsafeMappedDrives}
if ($UnsafeLogonScripts) {Show-Results $UnsafeLogonScripts}
if ($UnsafeGPOLogonScripts) {Show-Results $UnsafeGPOLogonScripts}
if ($UnsafeUNCPermissions) {Show-Results $UnsafeUNCPermissions}
if ($UnsafeNetlogonSysvol) {Show-Results $UnsafeNetlogonSysvol}
if ($Credentials) {Show-Results $Credentials}
if ($NonExistentShares) {Show-Results $NonExistentShares}
if ($AdminLogonScripts) {Show-Results $AdminLogonScripts}
if ($ExploitableLogonScripts) {Show-Results $ExploitableLogonScripts}

if ($SaveOutput) {
    if ($UnsafeMappedDrives) {
        Write-Host "[i] Saving UnsafeMappedDrives.csv to the current directory" -ForegroundColor Cyan
        $UnsafeMappedDrives | Export-CSV -NoTypeInformation UnsafeMappedDrives.csv
    }
    if ($UnsafeLogonScripts) {
        Write-Host "[i] Saving UnsafeLogonScripts.csv to the current directory" -ForegroundColor Cyan
        $UnsafeLogonScripts | Export-CSV -NoTypeInformation UnsafeLogonScripts.csv
    }
    if ($UnsafeGPOLogonScripts) {
        Write-Host "[i] Saving UnsafeGPOLogonScripts.csv to the current directory" -ForegroundColor Cyan
        $UnsafeGPOLogonScripts | Export-Csv -NoTypeInformation UnsafeGPOLogonScripts.csv
    }
    if ($UnsafeUNCPermissions) {
        Write-Host "[i] Saving UnsafeUNCPermissions.csv to the current directory" -ForegroundColor Cyan
        $UnsafeUNCPermissions | Export-CSV -NoTypeInformation UnsafeUNCPermissions.csv
    }
    if ($UnsafeNetlogonSysvol) {
        Write-Host "[i] Saving UnsafeNetlogonSysvol.csv to the current directory" -ForegroundColor Cyan
        $UnsafeNetlogonSysvol | Export-Csv -NoTypeInformation UnsafeNetlogonSysvol.csv
    }
    if ($AdminLogonScripts) {
        Write-Host "[i] Saving AdminLogonScripts.csv to the current directory" -ForegroundColor Cyan
        $AdminLogonScripts | Export-CSV -NoTypeInformation AdminLogonScripts.csv
    }
    if ($Credentials) {
        Write-Host "[i] Saving Credentials.csv to the current directory" -ForegroundColor Cyan
        $Credentials | Export-CSV -NoTypeInformation Credentials.csv
    }
    if ($NonExistentShares) {
        Write-Host "[i] Saving NonExistentShares.csv to the current directory" -ForegroundColor Cyan
        $NonExistentShares | Export-CSV -NoTypeInformation NonExistentShares.csv
    }
    if ($ExploitableLogonScripts) {
        Write-Host "[i] Saving ExploitableLogonScripts.csv to the current directory" -ForegroundColor Cyan
        $ExploitableLogonScripts | Export-CSV -NoTypeInformation ExploitableLogonScripts.csv
    }

    Get-ChildItem -Filter "*.csv" -File
}
}