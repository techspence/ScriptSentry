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
    foreach ($script in $LogonScripts){
        $ACL = (Get-Acl $script.FullName).Access
        foreach ($entry in $ACL) {
            if ($entry.FileSystemRights -match $UnsafeRights `
                -and $entry.AccessControlType -eq "Allow" `
                -and $entry.IdentityReference -notmatch $SafeUsers
                ){
                    Write-Host "`n[!] UNSAFE ACL FOUND!"
                    Write-Host "- File: $($script.FullName)"
                    Write-Host "- User: $($entry.IdentityReference.Value)"
                    Write-Host "- Rights: $($entry.FileSystemRights)"
                    Write-Host ""
            }
        }
    }
}