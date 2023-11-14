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
| Done | Added support for finding nonexistent shares | Checks DNS for file shares that don't exist|
| Done | Write a blog post about this tool/why I made it | Link to blog post below|
| Done | Add check for Logon Scripts that have been configured via GPO | Implemented|
| Done | Slight changes to NETLOGON & SYSVOL misconfiguration check & result output |Implemented|
| Done | Simplified the project. Maybe someday I will build an actual PSGallery Module |Implemented|
| Done | ScriptSentry now checks all admins for logonscripts not just domain admins| Implemented|
| Done | Added a couple PowerView functions to make group/user searching easier|Implemented|
| In progress | Additional regex to search for other dangerous stuff in logon scripts | More detections in the pipeline |

### Read the blog post
https://offsec.blog/hidden-menace-how-to-identify-misconfigured-and-dangerous-logon-scripts/

### Installing & Running
```PowerShell
# Clone, run, and display results on the console
git clone https://github.com/techspence/ScriptSentry
.\Invoke-ScriptSentry.ps1

# Run ScriptSentry and save results to a text file
.\Invoke-ScriptSentry.ps1 | Out-File c:\temp\ScriptSentry.txt

# Run ScriptSentry and save results to separate csv files in the current directory
.\Invoke-ScriptSentry.ps1 -SaveOutput $true


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
                                          v0.4
                                      __,_______
                                     / __.==---/ * * * * * *
                                    / (-'
                                    `-'
                            Setting phasers to stun, please wait..

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
UnsafeLogonScriptPermission \\eureka.local\sysvol\eureka.local\scripts\run.vbs     NT AUTHORITY\Authenticated Users ReadAndExecute, Synchronize
UnsafeLogonScriptPermission \\eureka.local\sysvol\eureka.local\scripts\test.cmd    EUREKA\Domain Users                      Modify, Synchronize


########## Unsafe GPO logon script permissions ##########

Type                           File                             User                                        Rights
----                           ----                             ----                                        ------
UnsafeGPOLogonScriptPermission \\eureka-dc01\fileshare1\run.bat EUREKA\testuser Write, ReadAndExecute, Synchronize
UnsafeGPOLogonScriptPermission \\eureka-dc01\fileshare1\run.bat Everyone                               FullControl


########## Unsafe UNC file permissions ##########

Type                    File                                              User                                        Rights
----                    ----                                              ----                                        ------
UnsafeUNCFilePermission \\eureka-dc01\fileshare1\IT\securit360pentest.bat Everyone                               FullControl


########## Unsafe NETLOGON/SYSVOL permissions ##########

Type                 Folder                  User                                          Rights
----                 ------                  ----                                          ------
UnsafeNetlogonSysvol \\eureka.local\NETLOGON EUREKA\Domain Users              Modify, Synchronize
UnsafeNetlogonSysvol \\eureka.local\SYSVOL   NT AUTHORITY\Authenticated Users Modify, Synchronize

########## Plaintext credentials ##########

Type        File                                                   Credential
----        ----                                                   ----------
Credentials \\eureka.local\sysvol\eureka.local\scripts\ADCheck.ps1 $password = ConvertTo-SecureString -String "Password2468!" -AsPlainText -Force
Credentials \\eureka.local\sysvol\eureka.local\scripts\shares.cmd  net use f: \\eureka-dc01\fileshare1\it /user:itadmin Password2468!
Credentials \\eureka.local\sysvol\eureka.local\scripts\test.cmd    net use g: \\eureka-dc01\fileshare1 /user:user1 Password3355!
Credentials \\eureka.local\sysvol\eureka.local\scripts\test.cmd    net use h: \\eureka-dc01\fileshare1\accounting /user:userfoo Password5!

########## Nonexistent Shares ##########

Type             Server             Share                                 Script                                                   DNS Exploitable Admins
----             ------             -----                                 ------                                                   --- ----------- ------
NonexistentShare CUHOLDING          \\CUHOLDING\QUICKBOOKS                \\eureka.local\sysvol\eureka.local\scripts\marketing.bat No  Potentially No    
NonexistentShare eureka-srvnotexist \\eureka-srvnotexist\NonExistingShare \\eureka.local\sysvol\eureka.local\scripts\test.cmd      No  Potentially No    
NonexistentShare NAS                \\NAS\PUBLIC                          \\eureka.local\sysvol\eureka.local\scripts\main.bat      No  Potentially No    
NonexistentShare NAS                \\NAS\SYMITAR                         \\eureka.local\sysvol\eureka.local\scripts\symregOLD.bat No  Potentially No    

########## Admins with logonscripts ##########

Type             User                                                      LogonScript
----             ----                                                      -----------
AdminLogonScript LDAP://CN=Administrator,CN=Users,DC=eureka,DC=local       run.vbs
AdminLogonScript LDAP://CN=it admin,OU=Admins,OU=Eureka,DC=eureka,DC=local elevate.vbs

########## Exploitable logon scripts ##########

Type                   Server             Share                                 Script                                              DNS Exploitable Admins                                                                
----                   ------             -----                                 ------                                              --- ----------- ------                                                                
ExploitableLogonScript eureka-srvnotexist \\eureka-srvnotexist\NonExistingShare \\eureka.local\sysvol\eureka.local\scripts\test.cmd No  Yes  LDAP://eureka.local/CN=it admin,OU=Admins,OU=Eureka,DC=eureka,DC=local
ExploitableLogonScript eureka-srvnotexist \\eureka-srvnotexist\NonExistingShare \\eureka.local\sysvol\eureka.local\scripts\test.cmd No  Yes  LDAP://eureka.local/CN=user1,OU=Users,OU=Eureka,DC=eureka,DC=local  
```