function Find-UNCScripts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )

    $UNCFiles = @()
    foreach ($script in $LogonScripts) {
        $UNCFiles += Get-Content $script.FullName | Select-String -Pattern '\\.*\.\w+' | foreach {$_.Matches.Value}
    }
    Write-Verbose "[+] UNC scripts:"
    $UNCFiles | ForEach-Object {
        Write-Verbose -Message "$_"
    }
    return $UNCFiles
}