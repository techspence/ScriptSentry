function Find-LogonScriptCredentials {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )
    foreach ($script in $LogonScripts) {
        # Write-Verbose -Message "Checking $($Script.FullName) for credentials.."
        $Credentials = Get-Content -Path $script.FullName | Select-String -Pattern "/user:","-AsPlainText" -AllMatches
        if ($Credentials) {
            # "`n[!] CREDENTIALS FOUND!"
            $Credentials | ForEach-Object {
                $Results = [ordered] @{
                    Type = 'Credentials'
                    File = $script.FullName
                    Credential = $_
                }
                [pscustomobject] $Results | Sort-Object -Unique
            }
        }
    }
}