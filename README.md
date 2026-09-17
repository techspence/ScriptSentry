# ScriptSentry
![ScriptSentry](ScriptSentry.png)

ScriptSentry finds misconfigured and dangerous logon scripts.

### Read the blog post
https://offsec.blog/hidden-menace-how-to-identify-misconfigured-and-dangerous-logon-scripts/

### Usage
```PowerShell
# Run ScriptSentry and display results on the console
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/techspence/ScriptSentry/main/Invoke-ScriptSentry.ps1')
Invoke-ScriptSentry

# Run ScriptSentry and save output to a text file
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/techspence/ScriptSentry/main/Invoke-ScriptSentry.ps1')
Invoke-ScriptSentry | Out-File c:\temp\ScriptSentry.txt

# Run ScriptSentry and save results to ScriptSentryResults.csv in the current directory
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/techspence/ScriptSentry/main/Invoke-ScriptSentry.ps1')
Invoke-ScriptSentry -SaveOutput $true

# Save results to a specific directory
Invoke-ScriptSentry -SaveOutput $true -OutputDirectory C:\Temp\ScriptSentry

# Use alternate credentials for LDAP queries
$Credential = Get-Credential
Invoke-ScriptSentry -Credential $Credential

# Query a specific domain controller and domain
Invoke-ScriptSentry -Server DC01.contoso.com -Domain contoso.com

# Query a specific domain controller with alternate credentials
Invoke-ScriptSentry -Server DC01.contoso.com -Domain contoso.com -Credential $Credential
```

`-Server` and `-Domain` must be used together. `-Credential` applies to LDAP queries; SYSVOL, NETLOGON, and other UNC paths are accessed as the user running PowerShell.

### Example Output
```
########## Plaintext credentials ##########

Misconfiguration Description                                 Details
---------------- -----------                                 -------
LSM-Creds        Plaintext credentials within a logon script \\contoso.com\sysvol\contoso.com\scripts\logon.bat - net use Z: \\FS01\Tools /user:CONTOSO\svc.deploy [REDACTED]

########## Unsafe UNC folder permissions ##########

Misconfiguration Description                   Details
---------------- -----------                   -------
LSM-Access-1     Unsafe UNC folder permissions CONTOSO\Domain Users with Modify on \\FS01\Tools

########## Unsafe UNC file permissions ##########

Misconfiguration Description                 Details
---------------- -----------                 -------
LSM-Access-2     Unsafe UNC file permissions CONTOSO\Domain Users with Modify on \\FS01\Tools\startup.ps1

########## Unsafe NETLOGON/SYSVOL permissions ##########

Misconfiguration Description                        Details
---------------- -----------                        -------
LSM-Access-3     Unsafe NETLOGON/SYSVOL permissions CONTOSO\Domain Users with Modify on \\contoso.com\NETLOGON

########## Unsafe logon script permissions ##########

Misconfiguration Description                     Details
---------------- -----------                     -------
LSM-Access-4     Unsafe logon script permissions CONTOSO\Domain Users with Modify on \\contoso.com\sysvol\contoso.com\scripts\logon.bat

########## Unsafe GPO logon script permissions ##########

Misconfiguration Description                         Details
---------------- -----------                         -------
LSM-Access-5     Unsafe GPO logon script permissions CONTOSO\Domain Users with Modify on \\contoso.com\NETLOGON\logon.bat

########## Admins with logonscripts ##########

Misconfiguration Description              Details
---------------- -----------              -------
LSM-Admins-1     Admins with logonscripts CN=Administrator,CN=Users,DC=contoso,DC=com - logon.bat

########## Nonexistent Shares ##########

Misconfiguration Description         Details
---------------- -----------         -------
LSM-Shares       Non-existent shares \\OLD-FS01\Legacy mapped in \\contoso.com\sysvol\contoso.com\scripts\logon.bat

########## Admins with logonscripts mapped from nonexistent share ##########

Misconfiguration Description                                             Details
---------------- -----------                                             -------
LSM-Admins-2     Admins with logonscripts mapped from nonexistent share CN=Administrator,CN=Users,DC=contoso,DC=com - logon.bat mapping \\OLD-FS01\Legacy
```
