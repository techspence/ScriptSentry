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
        Write-Verbose -Message "Checking $($script.FullName) for unsafe permissions.."
        $ACL = (Get-Acl $script.FullName).Access
        foreach ($entry in $ACL) {
            if ($entry.FileSystemRights -match $UnsafeRights `
                -and $entry.AccessControlType -eq "Allow" `
                -and $entry.IdentityReference -notmatch $SafeUsers
                ){
                    Write-Output "`n[!] UNSAFE ACL FOUND!"
                    Write-Output "- File: $($script.FullName)"
                    Write-Output "- User: $($entry.IdentityReference.Value)"
                    Write-Output "- Rights: $($entry.FileSystemRights)"
                    Write-Output ""
            }
        }
    }
}