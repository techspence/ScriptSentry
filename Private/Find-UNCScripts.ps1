function Find-UNCScripts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )

    $ExcludedMatches = "copy|&|/command|%WINDIR%|-i"
    $UNCFiles = @()
    [Array] $UNCFiles = foreach ($script in $LogonScripts) {
        $MatchingUNCFiles = Get-Content $script.FullName | Select-String -Pattern '\\\\.*\.\w+' | ForEach-Object { $_.Matches.Value }
        $MatchingUNCFiles | Foreach-object {
            if ($_ -match $ExcludedMatches) {
                # don't collect
            } else {
                $_
            }
        }
    }
    Write-Verbose "[+] UNC scripts:"
    $UNCFiles | ForEach-Object {
        Write-Verbose -Message "$_"
    }
    
    $UNCFiles | Sort-Object -Unique
}