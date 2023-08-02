<#
.SYNOPSIS
ScriptSentry finds misconfigured and dangerous logon scripts.

.DESCRIPTION
ScriptSentry searches the NETLOGON share to 
    1) identify plaintext credentials in logon scripts
    2) identify admins that have logon script set 
    3) identify scripts and shares that may have dangerous permissions

.EXAMPLE
Invoke-ScriptSentry

.EXAMPLE
Invoke-ScriptSentry | Out-File c:\temp\ScriptSentry.txt

.EXAMPLE
ScriptSentry.ps1

#>
[CmdletBinding()]
Param()

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
    $searcher.PropertiesToLoad.Add("samaccountname") | Out-Null
    $searcher.PropertiesToLoad.Add("scriptPath") | Out-Null

    # Execute the search
    $results = $searcher.FindAll()

    # Filter the results based on scriptPath and memberOf properties
    $AdminLogonScripts = $results | Where-Object { $_.Properties["scriptPath"] -ne $null -and ($adminGroups -match $AdminGroups) }

    "`n[!] Admins found with logon scripts"
    $AdminLogonScripts | ForEach-Object {
        "- User: $($_.Path)"
        "- logonscript: $($_.Properties.scriptpath)"
        ""    
    }   
}
function Find-LogonScriptCredentials {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )
    foreach ($script in $LogonScripts) {
        Write-Verbose -Message "Checking $($Script.FullName) for credentials.."
        $Credentials = Get-Content -Path $script.FullName | Select-String -Pattern "/user:" -AllMatches
        if ($Credentials) {
            "`n[!] CREDENTIALS FOUND!"
            "- File: $($script.FullName)"
            $Credentials | ForEach-Object {
                "`t- Credential: $_"
            }
            ""
        }
    } 
}
function Find-UNCScripts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )

    $UNCFiles = @()
    [Array] $UNCFiles = foreach ($script in $LogonScripts) {
        Get-Content $script.FullName | Select-String -Pattern '\\.*\.\w+' | ForEach-Object { $_.Matches.Value }
    }
    Write-Verbose "[+] UNC scripts:"
    $UNCFiles | ForEach-Object {
        Write-Verbose -Message "$_"
    }
    
    $UNCFiles
}
function Find-MappedDrives {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )

    $Shares = @()
    [Array] $Shares = foreach ($script in $LogonScripts) {
        # Kind of messy, but it works? Could not get the regex 100% perfect
        $temp = Get-Content $script.FullName | Select-String -Pattern '\\\\[\w\.\-]+\\[\w\-_\\.]+' | ForEach-Object { $_.Matches.Value } 
        $temp | ForEach-Object {
            if ($_ -match '\.') {
                (Get-Item $_).Directory.FullName
            } else {
                $_
            }
        }
    }
    $Shares | Sort-Object -Unique
}
function Find-UnsafeLogonScriptPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )

    $DomainAdmins = Get-DomainAdmins
    $SafeUsers = 'NT AUTHORITY\\SYSTEM|Administrator'
    $DomainAdmins | ForEach-Object { $SafeUsers = $SafeUsers + '|' + $_ }
    foreach ($script in $LogonScripts) {
        Write-Verbose -Message "Checking $($script.FullName) for unsafe permissions.."
        $ACL = (Get-Acl $script.FullName).Access
        foreach ($entry in $ACL) {
            if ($entry.FileSystemRights -match $UnsafeRights `
                    -and $entry.AccessControlType -eq "Allow" `
                    -and $entry.IdentityReference -notmatch $SafeUsers
            ) {
                "`n[!] UNSAFE ACL FOUND!"
                "- File: $($script.FullName)"
                "- User: $($entry.IdentityReference.Value)"
                "- Rights: $($entry.FileSystemRights)"
                ""
            }
        }
    }
}
function Find-UnsafeUNCPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$UNCScripts
    )

    $UnsafeRights = 'FullControl|Modify|Write'
    $DomainAdmins = $DomainAdmins = Get-DomainAdmins
    $SafeUsers = 'NT AUTHORITY\\SYSTEM|Administrator'
    $DomainAdmins | ForEach-Object { $SafeUsers = $SafeUsers + '|' + $_ }
    foreach ($script in $UNCScripts) {
        Write-Verbose -Message "Checking $script for unsafe permissions.."
        $ACL = (Get-Acl $script).Access
        foreach ($entry in $ACL) {
            if ($entry.FileSystemRights -match $UnsafeRights `
                    -and $entry.AccessControlType -eq "Allow" `
                    -and $entry.IdentityReference -notmatch $SafeUsers
            ) {
                "`n[!] UNSAFE ACL FOUND!"
                "- File: $script"
                "- User: $($entry.IdentityReference.Value)"
                "- Rights: $($entry.FileSystemRights)"
                ""
            }
        }
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

"
}
function Get-DomainAdmins {
    [CmdletBinding()]
    param()

    $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

    # Set the distinguished name of the "Domain Admins" group (update this with the correct DN)
    $domainAdminsGroupDN = "CN=Domain Admins,CN=Users,DC=$($($currentDomain.Name).split('.')[0]),DC=$($($currentDomain.Name).split('.')[1])"

    # Create a new ADSI searcher object for the "Domain Admins" group
    $searcher = [adsisearcher]"(distinguishedName=$domainAdminsGroupDN)"

    # Specify the property to retrieve (samaccountname of members)
    $searcher.PropertiesToLoad.Add("member") | Out-Null

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
function Get-LogonScripts {
    [CmdletBinding()]
    param()

    # Get the current domain name from the environment
    $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

    # $SysvolScripts = '\\' + (Get-ADDomain).DNSRoot + '\sysvol\' + (Get-ADDomain).DNSRoot + '\scripts'
    $SysvolScripts = "\\$($currentDomain.Name)\sysvol\$($currentDomain.Name)\scripts"
    $ExtensionList = '.bat|.vbs|.ps1|.cmd'
    $LogonScripts = Get-ChildItem -Path $SysvolScripts -Recurse | Where-Object { $_.Extension -match $ExtensionList }
    Write-Verbose "[+] Logon scripts:"
    $LogonScripts | ForEach-Object {
        Write-Verbose -Message "$($_.fullName)"
    }
    $LogonScripts
}

Get-Art -Version '0.1'

# Get a list of all logon scripts
$LogonScripts = Get-LogonScripts

# Find logon scripts (.bat, .vbs, .cmd, .ps1) that contain unc paths (e.g. \\srv01\fileshare1)
$UNCScripts = Find-UNCScripts -LogonScripts $LogonScripts

# Find mapped drives (e.g. \\srv01\fileshare1, \\srv02\fileshare2\accounting)
$MappedDrives = Find-MappedDrives -LogonScripts $LogonScripts

# Find unsafe permissions for unc files found in logon scripts
Find-UnsafeUNCPermissions -UNCScripts $UNCScripts

# Find unsafe permissions for unc paths found in logon scripts
Find-UnsafeUNCPermissions -UNCScripts $MappedDrives

# Find unsafe permissions on logon scripts
Find-UnsafeLogonScriptPermissions -LogonScripts $LogonScripts

# Find admins that have logon scripts assigned
Find-AdminLogonScripts

# Find credentials in logon scripts
Find-LogonScriptCredentials -LogonScripts $LogonScripts