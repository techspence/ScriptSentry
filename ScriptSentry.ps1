<#
.SYNOPSIS
ScriptSentry finds misconfigured and dangerous logon scripts.

.DESCRIPTION
ScriptSentry searches the NETLOGON share to 
    1) identify plaintext credentials in logon scripts
    2) identify admins that have logon script set 
    3) identify scripts and shares that may have dangerous permissions

.EXAMPLE
.\ScriptSentry.ps1

.EXAMPLE
.\ScriptSentry.ps1 c:\temp\ScriptSentry.txt

.EXAMPLE
.\ScriptSentry.ps1 -SaveOutput $true

#>

[CmdletBinding()]
Param(
    [boolean]$SaveOutput = $false
)

function Get-Domains {
    [CmdletBinding()]
    param()

    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $forest.Domains
}
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
function Get-LogonScripts {
    [CmdletBinding()]
    param()

    # Get the current domain name from the environment
    # $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $Domains = Get-Domains

    foreach ($Domain in $Domains) {
        # $SysvolScripts = '\\' + (Get-ADDomain).DNSRoot + '\sysvol\' + (Get-ADDomain).DNSRoot + '\scripts'
        $SysvolScripts = "\\$($Domain.Name)\sysvol\$($Domain.Name)\scripts"
        $ExtensionList = '.bat|.vbs|.ps1|.cmd'
        $LogonScripts = Get-ChildItem -Path $SysvolScripts -Recurse | Where-Object {$_.Extension -match $ExtensionList}
        Write-Verbose "[+] Logon scripts:"
        $LogonScripts | ForEach-Object {
            Write-Verbose -Message "$($_.fullName)"
        }
        $LogonScripts | Sort-Object -Unique
    }
}
function Find-AdminLogonScripts {
    # Write-Verbose -Message "Checking for admins who have logon scripts set.."

    $Domains = Get-Domains

    foreach ($Domain in $Domains) {
        
        # Enabled user accounts
        $ldapFilter = "(&(objectCategory=User)(objectClass=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

        # Admin groups to match on
        $AdminGroups = "Account Operators|Administrators|Backup Operators|Cryptographic Operators|Distributed COM Users|Domain Admins|Domain Controllers|Enterprise Admins|Print Operators|Schema Admins|Server Operators"

        # Create a new ADSI searcher object
        # $searcher = [adsisearcher]$ldapFilter
        $searcher = New-Object DirectoryServices.DirectorySearcher([adsi]"LDAP://$($Domain.Name)", $ldapFilter)

        # Specify the properties to retrieve
        $searcher.PropertiesToLoad.Add("samaccountname") | out-null
        $searcher.PropertiesToLoad.Add("scriptPath") | out-null
        $searcher.PropertiesToLoad.Add("memberOf") | out-null

        # Execute the search
        $results = $searcher.FindAll()

        # Filter the results based on scriptPath and memberOf properties
        $AdminLogonScripts = $results | Where-Object { $_.Properties["scriptPath"] -ne $null -and ($_.Properties["memberOf"] -match $AdminGroups) }

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
}
function Find-LogonScriptCredentials {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )
    foreach ($script in $LogonScripts) {
        # Write-Verbose -Message "Checking $($Script.FullName) for credentials.."
        $Credentials = Get-Content -Path $script.FullName | Select-String -Pattern "/user:","-AsPlainText" -AllMatches
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
        $MatchingUNCFiles = Get-Content $script.FullName | Select-String -Pattern '\\\\.*\.\w+' | ForEach-Object { $_.Matches.Value }
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
        $temp = Get-Content $script.FullName | Select-String -Pattern '.*net use.*','New-SmbMapping','.MapNetworkDrive' | ForEach-Object { $_.Matches.Value } 
        $temp = $temp | Select-String -Pattern '\\\\[\w\.\-]+\\[\w\-_\\.]+' | ForEach-Object { $_.Matches.Value }
        $temp | ForEach-Object {
            try {
                $Path = "$_"
                (Get-Item $Path -ErrorAction Stop).FullName
            } catch [System.UnauthorizedAccessException] {
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
function Get-NetlogonSysvol {
    [CmdletBinding()]
    param()

    $Domains = Get-Domains
    foreach ($Domain in $Domains){
        "\\$($Domain.Name)\NETLOGON"
        "\\$($Domain.Name)\SYSVOL"
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
                if ($script -match 'NETLOGON' -or $script -match 'SYSVOL') {
                    $Type = 'UnsafeUNCFolderPermission'
                }
                elseif ($script -match '\.') {
                    $Type = 'UnsafeUNCFilePermission'
                } else {
                    $Type = 'UnsafeUNCFolderPermission'
                }
                $Results = [ordered] @{
                    Type = $Type
                    File = $script
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
        Credentials                 = 'Plaintext credentials'
        AdminLogonScript            = 'Admins with logonscripts'
        UnsafeUNCFilePermission     = 'Unsafe UNC file permissions'
        UnsafeUNCFolderPermission   = 'Unsafe UNC folder permissions'
        UnsafeLogonScriptPermission = 'Unsafe logon script permissions'
    }

    if ($null -ne $Results) {
        $UniqueResults = $Results.Type | Sort-Object -Unique
        Write-Host "########## $($IssueTable[$UniqueResults]) ##########"
        # $Results | Format-List
        $Results | Format-Table -Wrap
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

Get-Art -Version '0.3'

$SafeUsers = 'NT AUTHORITY\\SYSTEM|Administrator|NT SERVICE\\TrustedInstaller|Domain Admins|Server Operators|Enterprise Admins'
$DomainAdmins = $DomainAdmins = Get-DomainAdmins
$DomainAdmins | ForEach-Object { $SafeUsers = $SafeUsers + '|' + $_ }

# Get a list of all logon scripts
$LogonScripts = Get-LogonScripts

# Find logon scripts (.bat, .vbs, .cmd, .ps1) that contain unc paths (e.g. \\srv01\fileshare1)
$UNCScripts = Find-UNCScripts -LogonScripts $LogonScripts

# Find mapped drives (e.g. \\srv01\fileshare1, \\srv02\fileshare2\accounting)
$MappedDrives = Find-MappedDrives -LogonScripts $LogonScripts

# Find unsafe permissions for unc files found in logon scripts
$UnsafeUNCPermissions = Find-UnsafeUNCPermissions -UNCScripts $UNCScripts -SafeUsersList $SafeUsers

# Find unsafe permissions for unc paths found in logon scripts
$UnsafeMappedDrives = Find-UnsafeUNCPermissions -UNCScripts $MappedDrives -SafeUsersList $SafeUsers

# Find unsafe NETLOGON & SYSVOL share permissions
$NetlogonSysvol = Get-NetlogonSysvol
$UnsafeNetlogonSysvol = Find-UnsafeUNCPermissions -UNCScripts $NetlogonSysvol -SafeUsersList $SafeUsers

# Find unsafe permissions on logon scripts
$UnsafeLogonScripts = Find-UnsafeLogonScriptPermissions -LogonScripts $LogonScripts -SafeUsersList $SafeUsers

# Find admins that have logon scripts assigned
$AdminLogonScripts = Find-AdminLogonScripts

# Find credentials in logon scripts
$Credentials = Find-LogonScriptCredentials -LogonScripts $LogonScripts

# Show all results
Show-Results $UnsafeMappedDrives
Show-Results $UnsafeLogonScripts
Show-Results $UnsafeUNCPermissions
Show-Results $UnsafeNetlogonSysvol
Show-Results $AdminLogonScripts
Show-Results $Credentials

if ($SaveOutput) {
    $UnsafeMappedDrives | Export-CSV -NoTypeInformation UnsafeMappedDrives.csv
    $UnsafeLogonScripts | Export-CSV -NoTypeInformation UnsafeLogonScripts.csv
    $UnsafeUNCPermissions | Export-CSV -NoTypeInformation UnsafeUNCPermissions.csv
    $AdminLogonScripts | Export-CSV -NoTypeInformation AdminLogonScripts.csv
    $Credentials | Export-CSV -NoTypeInformation Credentials.csv
}