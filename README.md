# ScriptSentry
![ScriptSentry](ScriptSentry.png)

ScriptSentry finds misconfigured and dangerous logon scripts.

### Additional Planned Features
| status | Feature | Notes |
| ------ | ------ | ------ |
| Done | make output an object | Testing successful
| Done | Multi domain/forest support | Added multi-domain support |
| Done | Check for misconfigured NETLOGON and SYSVOL share | Added check for unsafe permissions |
| Done | Add additional mapped drive checks | Added check for mapped drives via New-SmbMapping (pwsh) & .MapNetworkDrive (vbs)|
| Done | Improved the ASCII art | Because its fun|
| Done | Improved regex to reduce false positives | Because regex is hard|
| In progress | Additional regex to search for other dangerous stuff in logon scripts | More detections in the pipeline |
| ToDo | Write a blog post about this tool/why I made it | |
| ToDo | Create an official release | |
| ToDo | Publish to PSGallery | |


### Installing & Running
```PowerShell
# Clone, import and run, display results on the console
git clone https://github.com/techspence/ScriptSentry
Import-Module ScriptSentry.psm1
Invoke-ScriptSentry

# Run ScriptSentry and save results to a text file
Invoke-ScriptSentry | Out-File c:\temp\ScriptSentry.txt

# Run ScriptSentry and save results to separate csv files in the current directory
Invoke-ScriptSentry -SaveOutput $true

# Run the standalone ScriptSentry script
git clone https://github.com/techspence/ScriptSentry
ScriptSentry.ps1

# Customize & build it yourself
git clone https://github.com/techspence/ScriptSentry
.\Build\Build-Module.ps1
Import-Module ScriptSentry.psm1
Invoke-ScriptSentry
```

### Example Output
```
 _______  _______  _______ _________ _______ _________ _______  _______  _       _________ _______
(  ____ \(  ____ \(  ____ )\__   __/(  ____ )\__   __/(  ____ \(  ____ \( (    /|\__   __/(  ____ )|\     /|
| (    \/| (    \/| (    )|   ) (   | (    )|   ) (   | (    \/| (    \/|  \  ( |   ) (   | (    )|( \   / )
| (_____ | |      | (____)|   | |   | (____)|   | |   | (_____ | (__    |   \ | |   | |   | (____)| \ (_) /
(_____  )| |      |     __)   | |   |  _____)   | |   (_____  )|  __)   | (\ \) |   | |   |     __)  \   /
      ) || |      | (\ (      | |   | (         | |         ) || (      | | \   |   | |   | (\ (      ) (
/\____) || (____/\| ) \ \_____) (___| )         | |   /\____) || (____/\| )  \  |   | |   | ) \ \__   | |
\_______)(_______/|/   \__/\_______/|/          )_(   \_______)(_______/|/    )_)   )_(   |/   \__/   \_/
                              by: Spencer Alessi @techspence
                                          v0.3


########## Unsafe UNC folder permissions ##########

Type                      File                                User          Rights
----                      ----                                ----          ------
UnsafeUNCFolderPermission \\eureka-dc01\fileshare1            Everyone FullControl
UnsafeUNCFolderPermission \\eureka-dc01\fileshare1\accounting Everyone FullControl
UnsafeUNCFolderPermission \\eureka-dc01\fileshare1\IT         Everyone FullControl


########## Unsafe logon script permissions ##########

Type                        File                                                   User                                                  Rights
----                        ----                                                   ----                                                  ------
UnsafeLogonScriptPermission \\eureka.local\sysvol\eureka.local\scripts\elevate.vbs NT AUTHORITY\Authenticated Users ReadAndExecute, Synchronize
UnsafeLogonScriptPermission \\eureka.local\sysvol\eureka.local\scripts\elevate.vbs BUILTIN\Server Operators         ReadAndExecute, Synchronize
UnsafeLogonScriptPermission \\eureka.local\sysvol\eureka.local\scripts\run.vbs     NT AUTHORITY\Authenticated Users ReadAndExecute, Synchronize
UnsafeLogonScriptPermission \\eureka.local\sysvol\eureka.local\scripts\run.vbs     BUILTIN\Server Operators         ReadAndExecute, Synchronize
UnsafeLogonScriptPermission \\eureka.local\sysvol\eureka.local\scripts\test.cmd    EUREKA\Domain Users                      Modify, Synchronize


########## Unsafe UNC file permissions ##########

Type                    File                                              User                                        Rights
----                    ----                                              ----                                        ------
UnsafeUNCFilePermission \\eureka-dc01\fileshare1\IT\securit360pentest.bat Everyone                               FullControl
UnsafeUNCFilePermission \\eureka-dc01\fileshare1\run.bat                  EUREKA\testuser Write, ReadAndExecute, Synchronize
UnsafeUNCFilePermission \\eureka-dc01\fileshare1\run.bat                  Everyone                               FullControl


########## Admins with logonscripts ##########

Type             User                                                      LogonScript
----             ----                                                      -----------
AdminLogonScript LDAP://CN=Administrator,CN=Users,DC=eureka,DC=local       run.vbs
AdminLogonScript LDAP://CN=it admin,OU=Admins,OU=Eureka,DC=eureka,DC=local elevate.vbs


########## Plaintext credentials ##########

Type        File                                                   Credential
----        ----                                                   ----------
Credentials \\eureka.local\sysvol\eureka.local\scripts\ADCheck.ps1 $password = ConvertTo-SecureString -String "Password2468!" -AsPlainText -Force
Credentials \\eureka.local\sysvol\eureka.local\scripts\shares.cmd  net use f: \\eureka-dc01\fileshare1\it /user:itadmin Password2468!
Credentials \\eureka.local\sysvol\eureka.local\scripts\test.cmd    net use g: \\eureka-dc01\fileshare1 /user:user1 Password3355!
Credentials \\eureka.local\sysvol\eureka.local\scripts\test.cmd    net use h: \\eureka-dc01\fileshare1\accounting /user:userfoo Password5!
```