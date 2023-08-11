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
        $ACL = (Get-Acl $script.FullName).Access
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