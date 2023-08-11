function Get-LogonScripts {
    [CmdletBinding()]
    param()

    # Get the current domain name from the environment
    # $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $Domains = Get-Domains

    foreach ($Domain in $Domains) {
        # $SysvolScripts = '\\' + (Get-ADDomain).DNSRoot + '\sysvol\' + (Get-ADDomain).DNSRoot + '\scripts'
        $SysvolScripts = "\\$($Domain.Name)\sysvol\$($Domain.Name)\scripts"
        $ExtensionList = '.bat|.vbs|.ps1|.cmd'
        $LogonScripts = Get-ChildItem -Path $SysvolScripts -Recurse | Where-Object {$_.Extension -match $ExtensionList}
        Write-Verbose "[+] Logon scripts:"
        $LogonScripts | ForEach-Object {
            Write-Verbose -Message "$($_.fullName)"
        }
        $LogonScripts | Sort-Object -Unique
    }
}