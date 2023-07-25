function Find-UNCScripts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )

    $UNCFiles = @()
    [Array] $UNCFiles = foreach ($script in $LogonScripts) {
        Get-Content $script.FullName | Select-String -Pattern '\\.*\.\w+' | ForEach-Object { $_.Matches.Value }
    }
    Write-Verbose "[+] UNC scripts:"
    $UNCFiles | ForEach-Object {
        Write-Verbose -Message "$_"
    }
    
    $UNCFiles
}