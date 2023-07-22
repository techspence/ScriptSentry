function Find-LogonScriptCredentials {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )
    foreach ($script in $LogonScripts) {
        $Credentials = Get-Content -Path $script.FullName | Select-String -Pattern "/user:" -AllMatches
        if ($Credentials) {
            Write-Host "`n[!] CREDENTIALS FOUND!"
            Write-Host "- File: $($script.FullName)"
            $Credentials | ForEach-Object {
                Write-Host "`t- Credential: $_"
            }
            Write-Host ""
        }
    } 
}