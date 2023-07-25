<#
.SYNOPSIS
ScriptSentry finds misconfigured and dangerous logon scripts.

.DESCRIPTION
ScriptSentry uses the Active Directory (AD) Powershell (PS) module to identify misconfigured 
and dangerous logon scripts.

.COMPONENT
ScriptSentry requires the AD PS module to be installed in the scope of the Current User.
If ScriptSentry does not identify the AD PS module as installed, it will attempt to
install the module. If module installation does not complete successfully,
ScriptSentry will fail.

.EXAMPLE
Invoke-ScriptSentry

.EXAMPLE
Invoke-ScriptSentry | Out-File c:\temp\ScriptSentry.txt

#>
[CmdletBinding()]
Param()

function Find-AdminLogonScripts {
    $AdminGroups = "Domain Admins|Enterprise Admins|Administrators"
    $AdminLogonScripts = Get-ADUser -Filter { Enabled -eq $true } -Properties samaccountname, scriptPath, memberOf `
    | Where-Object { $null -ne $_.scriptPath -and $_.MemberOf -match $AdminGroups }         
    Write-Output "`n[!] Admins found with logon scripts"
    Write-Output "- User: $($AdminLogonScripts.DistinguishedName)"
    Write-Output "- logonscript: $($AdminLogonScripts.scriptPath)"
    Write-Output ""              
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
            Write-Output "`n[!] CREDENTIALS FOUND!"
            Write-Output "- File: $($script.FullName)"
            $Credentials | ForEach-Object {
                Write-Output "`t- Credential: $_"
            }
            Write-Output ""
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
    foreach ($script in $LogonScripts) {
        $UNCFiles += Get-Content $script.FullName | Select-String -Pattern '\\.*\.\w+' | foreach { $_.Matches.Value }
    }
    Write-Verbose "[+] UNC scripts:"
    $UNCFiles | ForEach-Object {
        Write-Verbose -Message "$_"
    }
    return $UNCFiles
}
function Find-UnsafeLogonScriptPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )

    $UnsafeRights = 'FullControl|Modify|Write'
    $DomainAdmins = (Get-ADGroupMember 'Domain Admins').SamAccountName
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
                Write-Output "`n[!] UNSAFE ACL FOUND!"
                Write-Output "- File: $($script.FullName)"
                Write-Output "- User: $($entry.IdentityReference.Value)"
                Write-Output "- Rights: $($entry.FileSystemRights)"
                Write-Output ""
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
    $DomainAdmins = (Get-ADGroupMember 'Domain Admins').SamAccountName
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
                Write-Output "`n[!] UNSAFE ACL FOUND!"
                Write-Output "- File: $script"
                Write-Output "- User: $($entry.IdentityReference.Value)"
                Write-Output "- Rights: $($entry.FileSystemRights)"
                Write-Output ""
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
function Get-DomainNetlogon {
    [CmdletBinding()]
    param (
        [string]$Forest,
        [System.Management.Automation.PSCredential]$Credential
    )

    if ($Forest) {
        $Targets = $Forest
    }
    elseif ($InputPath) {
        $Domains = Get-Content $InputPath
    }
    else {
        if ($Credential) {
            $Targets = (Get-ADForest -Credential $Credential).Name
        }
        else {
            $Targets = (Get-ADForest).Name
        }
    }
    return $Targets
}
function Get-LogonScripts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Domain
    )
    $SysvolScripts = '\\' + (Get-ADDomain).DNSRoot + '\sysvol\' + (Get-ADDomain).DNSRoot + '\scripts'
    $ExtensionList = '.bat|.vbs|.ps1|.cmd'
    $LogonScripts = Get-ChildItem -Path $SysvolScripts -Recurse | Where-Object { $_.Extension -match $ExtensionList }
    Write-Verbose "[+] Logon scripts:"
    $LogonScripts | ForEach-Object {
        Write-Verbose -Message "$($_.fullName)"
    }
    return $LogonScripts
}
function Get-Prerequisites {
    # Check if ActiveDirectory PowerShell module is available, and attempt to install if not found
    if (-not(Get-Module -Name 'ActiveDirectory' -ListAvailable)) {
        $OS = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
        # 1 - workstation, 2 - domain controller, 3 - non-dc server
        if ($OS -gt 1) {
            # Attempt to install ActiveDirectory PowerShell module for Windows Server OSes, works with Windows Server 2012 R2 through Windows Server 2022
            Install-WindowsFeature -Name RSAT-AD-PowerShell
        }
        else {
            # Attempt to install ActiveDirectory PowerShell module for Windows Desktop OSes
            Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online
        }
    }
}

Get-Art -Version '0.1'

# Get a list of domains
$Targets = Get-DomainNetLogon

# Get a list of all logon scripts
$LogonScripts = Get-LogonScripts -Domain $Targets

# Find logon scripts that contain unc paths (e.g. \\srv01\fileshare1)
$UNCScripts = Find-UNCScripts -LogonScripts $LogonScripts

# Find unsafe permissions for unc paths found in logon scripts
Find-UnsafeUNCPermissions -UNCScripts $UNCScripts

# Find unsafe permissions on logon scripts
Find-UnsafeLogonScriptPermissions -LogonScripts $LogonScripts

# Find admins that have logon scripts assigned
Find-AdminLogonScripts

# Find credentials in logon scripts
Find-LogonScriptCredentials -LogonScripts $LogonScripts