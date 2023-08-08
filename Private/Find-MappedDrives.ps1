function Find-MappedDrives {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )

    $Shares = @()
    [Array] $Shares = foreach ($script in $LogonScripts) {
        # Kind of messy, but it works? Could not get the regex 100% perfect
        $temp = Get-Content $script.FullName | Select-String -Pattern '\\\\[\w\.\-]+\\[\w\-_\\.]+' | ForEach-Object { $_.Matches.Value } 
        $temp | ForEach-Object {
            if ($_ -match '\.') {
                (Get-Item $_).Directory.FullName
            } else {
                $_
            }
        }
    }

    Write-Verbose "[+] Mapped drives:"
    $Shares | Sort-Object -Unique | ForEach-Object {
        Write-Verbose -Message "$_"
    }

    $Shares | Sort-Object -Unique
}