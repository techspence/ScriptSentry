function Show-Results {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results
    )

    $IssueTable = @{
        Credentials                 = 'Plaintext credentials'
        NonexistentShare            = 'Nonexistent Shares'
        AdminLogonScript            = 'Admins with logonscripts'
        UnsafeUNCFilePermission     = 'Unsafe UNC file permissions'
        UnsafeUNCFolderPermission   = 'Unsafe UNC folder permissions'
        UnsafeLogonScriptPermission = 'Unsafe logon script permissions'
    }

    if ($null -ne $Results) {
        $UniqueResults = $Results.Type | Sort-Object -Unique
        Write-Host "########## $($IssueTable[$UniqueResults]) ##########"
        # $Results | Format-List
        $Results | Format-Table -Wrap
    }
}