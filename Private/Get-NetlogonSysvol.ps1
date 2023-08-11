function Get-NetlogonSysvol {
    [CmdletBinding()]
    param()

    $Domains = Get-Domains
    foreach ($Domain in $Domains){
        "\\$($Domain.Name)\NETLOGON"
        "\\$($Domain.Name)\SYSVOL"
    }
}