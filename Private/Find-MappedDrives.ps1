function Find-MappedDrives {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LogonScripts
    )

    $Shares = @()
    [Array] $Shares = foreach ($script in $LogonScripts) {
        $temp = Get-Content $script.FullName | Select-String -Pattern '.*net use.*','New-SmbMapping','.MapNetworkDrive' | ForEach-Object { $_.Matches.Value } 
        $temp = $temp | Select-String -Pattern '\\\\[\w\.\-]+\\[\w\-_\\.]+' | ForEach-Object { $_.Matches.Value }
        $temp | ForEach-Object {
            try {
                $Path = "$_"
                (Get-Item $Path -ErrorAction Stop).FullName
            } catch [System.UnauthorizedAccessException] {
                Write-Verbose "$_ : You do not have access to $Directory`n"
            }
            catch {
                Write-Verbose "An error occurred: $($_.Exception.Message)"
            }
        }
    }

    Write-Verbose "[+] Mapped drives:"
    $Shares | Sort-Object -Unique | ForEach-Object {
        Write-Verbose -Message "$_"
    }

    $Shares | Sort-Object -Unique
}