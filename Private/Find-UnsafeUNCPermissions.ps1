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
    foreach ($script in $UNCScripts){
        Write-Verbose -Message "Checking $script for unsafe permissions.."
        $ACL = (Get-Acl $script).Access
        foreach ($entry in $ACL) {
            if ($entry.FileSystemRights -match $UnsafeRights `
                -and $entry.AccessControlType -eq "Allow" `
                -and $entry.IdentityReference -notmatch $SafeUsers
                ){
                if ($script -match '\.') {
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
                [pscustomobject] $Results
            }
        }
    }
}