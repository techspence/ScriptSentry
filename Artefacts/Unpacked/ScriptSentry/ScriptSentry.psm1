function Find-AdminLogonScripts {
    $Admins = @()
    $AdminGroups = "Domain Admins|Enterprise Admins|Administrators"
    $AdminLogonScripts = Get-ADUser -Filter { Enabled -eq $true } -Properties samaccountname, scriptPath, memberOf `
    | Where-Object { $_.scriptPath -ne $null -and $_.MemberOf -match $AdminGroups }         
    Write-Host "`n[!] Admins found with logon scripts"
    Write-Host "- User: $($AdminLogonScripts.DistinguishedName)"
    Write-Host "- logonscript: $($AdminLogonScripts.scriptPath)"
    Write-Host ""              
}
function Find-LogonScriptCredentials {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )
    foreach ($script in $LogonScripts) {
        $Credentials = Get-Content -Path $script.FullName | Select-String -Pattern "/user:" -AllMatches
        if ($Credentials) {
            Write-Host "`n[!] CREDENTIALS FOUND!"
            Write-Host "- File: $($script.FullName)"
            $Credentials | ForEach-Object {
                Write-Host "`t- Credential: $_"
            }
            Write-Host ""
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
        $ACL = (Get-Acl $script.FullName).Access
        foreach ($entry in $ACL) {
            if ($entry.FileSystemRights -match $UnsafeRights `
                    -and $entry.AccessControlType -eq "Allow" `
                    -and $entry.IdentityReference -notmatch $SafeUsers
            ) {
                Write-Host "`n[!] UNSAFE ACL FOUND!"
                Write-Host "- File: $($script.FullName)"
                Write-Host "- User: $($entry.IdentityReference.Value)"
                Write-Host "- Rights: $($entry.FileSystemRights)"
                Write-Host ""
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
        $ACL = (Get-Acl $script).Access
        foreach ($entry in $ACL) {
            if ($entry.FileSystemRights -match $UnsafeRights `
                    -and $entry.AccessControlType -eq "Allow" `
                    -and $entry.IdentityReference -notmatch $SafeUsers
            ) {
                Write-Host "`n[!] UNSAFE ACL FOUND!"
                Write-Host "- File: $script"
                Write-Host "- User: $($entry.IdentityReference.Value)"
                Write-Host "- Rights: $($entry.FileSystemRights)"
                Write-Host ""
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

    return $LogonScripts
}
function Invoke-ScriptSentry {
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

    #>

    Get-Art -Version '0.1'

    # Get a list of domains
    $Targets = Get-DomainNetLogon

    # Get a list of all logon scripts
    $LogonScripts = Get-LogonScripts -Domain $Targets

    # Find logon scripts that contain unc paths (e.g. \\srv01\fileshare1)
    $UNCScripts = Find-UNCScripts -LogonScripts $LogonScripts

    # Find unsafe permissions for unc paths found in logon scripts
    $UnsafePermissions = Find-UnsafeUNCPermissions -UNCScripts $UNCScripts

    # Find unsafe permissions on logon scripts
    $UnsafeLogonScriptPermissions = Find-UnsafeLogonScriptPermissions -LogonScripts $LogonScripts

    # Find admins that have logon scripts assigned
    $AdminsWithLogonScripts = Find-AdminLogonScripts

    # Find credentials in logon scripts
    $LogonScriptCredentials = Find-LogonScriptCredentials -LogonScripts $LogonScripts
}

$ModuleFunctions = @{
}
[Array] $FunctionsAll = 'Invoke-ScriptSentry'
[Array] $AliasesAll = 
$AliasesToRemove = [System.Collections.Generic.List[string]]::new()
$FunctionsToRemove = [System.Collections.Generic.List[string]]::new()
foreach ($Module in $ModuleFunctions.Keys) {
    try {
        Import-Module -Name $Module -ErrorAction Stop
    }
    catch {
        foreach ($Function in $ModuleFunctions[$Module].Keys) {
            $FunctionsToRemove.Add($Function)
            $ModuleFunctions[$Module][$Function] | ForEach-Object {
                if ($_) {
                    $AliasesToRemove.Add($_)
                }
            }
        }
    }
}
$FunctionsToLoad = foreach ($Function in $FunctionsAll) {
    if ($Function -notin $FunctionsToRemove) {
        $Function
    }
}
$AliasesToLoad = foreach ($Alias in $AliasesAll) {
    if ($Alias -notin $AliasesToRemove) {
        $Alias
    }
}

Export-ModuleMember -Function @($FunctionsToLoad) -Alias @($AliasesToLoad)