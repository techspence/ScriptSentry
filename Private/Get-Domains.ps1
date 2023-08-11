function Get-Domains {
    [CmdletBinding()]
    param()

    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $forest.Domains
}