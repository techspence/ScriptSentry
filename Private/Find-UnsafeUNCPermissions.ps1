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