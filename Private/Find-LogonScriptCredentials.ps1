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
            Write-Output "`n[!] CREDENTIALS FOUND!"
            Write-Output "- File: $($script.FullName)"
            $Credentials | ForEach-Object {
                Write-Output "`t- Credential: $_"
            }
            Write-Output ""
        }
    } 
}