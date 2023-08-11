function Invoke-ScriptSentry {
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
}