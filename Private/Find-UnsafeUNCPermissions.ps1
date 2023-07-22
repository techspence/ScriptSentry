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
    foreach ($script in $UNCScripts){
        $ACL = (Get-Acl $script).Access
        foreach ($entry in $ACL) {
            if ($entry.FileSystemRights -match $UnsafeRights `
                -and $entry.AccessControlType -eq "Allow" `
                -and $entry.IdentityReference -notmatch $SafeUsers
                ){
                    Write-Host "`n[!] UNSAFE ACL FOUND!"
                    Write-Host "- File: $script"
                    Write-Host "- User: $($entry.IdentityReference.Value)"
                    Write-Host "- Rights: $($entry.FileSystemRights)"
                    Write-Host ""
            }
        }
    }
}