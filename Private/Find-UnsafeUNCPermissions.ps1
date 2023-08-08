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
        # Write-Verbose -Message "Checking $script for unsafe permissions.."
        try{
            $ACL = (Get-Acl $script -ErrorAction Stop).Access
        } catch [System.UnauthorizedAccessException] {
            Write-Host "$_ : You do not have access to $script`n"
        }
        catch {
            Write-Host "An error occurred: $($_.Exception.Message)"
        }
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