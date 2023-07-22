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