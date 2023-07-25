function Find-LogonScriptCredentials {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )
    foreach ($script in $LogonScripts) {
        Write-Verbose -Message "Checking $($Script.FullName) for credentials.."
        $Credentials = Get-Content -Path $script.FullName | Select-String -Pattern "/user:" -AllMatches
        if ($Credentials) {
            "`n[!] CREDENTIALS FOUND!"
            "- File: $($script.FullName)"
            $Credentials | ForEach-Object {
                "`t- Credential: $_"
            }
             ""
        }
    } 
}