function Get-DomainNetlogon {
    [CmdletBinding()]
    param (
        [string]$Forest,
        [System.Management.Automation.PSCredential]$Credential
    )

    if ($Forest) {
        $Targets = $Forest
    }
    elseif ($InputPath) {
        $Domains = Get-Content $InputPath
    } else {
        if ($Credential){
            $Targets = (Get-ADForest -Credential $Credential).Name
        } else {
            $Targets = (Get-ADForest).Name
        }
    }
    return $Targets
}