function Find-AdminLogonScripts {
    $AdminGroups = "Domain Admins|Enterprise Admins|Administrators"
    $AdminLogonScripts = Get-ADUser -Filter {Enabled -eq $true} -Properties samaccountname,scriptPath,memberOf `
                         | Where-Object {$null -ne $_.scriptPath -and $_.MemberOf -match $AdminGroups}         
    Write-Output "`n[!] Admins found with logon scripts"
    Write-Output "- User: $($AdminLogonScripts.DistinguishedName)"
    Write-Output "- logonscript: $($AdminLogonScripts.scriptPath)"
    Write-Output ""              
}