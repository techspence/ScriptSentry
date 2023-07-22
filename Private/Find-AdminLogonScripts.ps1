function Find-AdminLogonScripts {
    $Admins = @()
    $AdminGroups = "Domain Admins|Enterprise Admins|Administrators"
    $AdminLogonScripts = Get-ADUser -Filter {Enabled -eq $true} -Properties samaccountname,scriptPath,memberOf `
                         | Where-Object {$_.scriptPath -ne $null -and $_.MemberOf -match $AdminGroups}         
    Write-Host "`n[!] Admins found with logon scripts"
    Write-Host "- User: $($AdminLogonScripts.DistinguishedName)"
    Write-Host "- logonscript: $($AdminLogonScripts.scriptPath)"
    Write-Host ""              
}