# ScriptSentry
![ScriptSentry](ScriptSentry.png)

ScriptSentry finds misconfigured and dangerous logon scripts.

### Installing & Running
```PowerShell
# Clone, import and run, display results on the console
git clone https://github.com/techspence/ScriptSentry
Import-Module ScriptSentry.psm1
Invoke-ScriptSentry

# Run ScriptSentry and save results to a file
Invoke-ScriptSentry | Out-File c:\temp\ScriptSentry.txt

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
                                          v0.1                                
[!] UNSAFE ACL FOUND!
- File: \\eureka-dc01\fileshare1\run.bat
- User: EUREKA\testuser
- Rights: Write, ReadAndExecute, Synchronize

[!] Admins found with logon scripts
- User: LDAP://CN=Administrator,CN=Users,DC=eureka,DC=local
- logonscript: run.vbs

- User: LDAP://CN=it admin,OU=Admins,OU=Eureka,DC=eureka,DC=local
- logonscript: test.cmd

[!] CREDENTIALS FOUND!
- File: \\eureka.local\sysvol\eureka.local\scripts\test.cmd
        - Credential: net use g: \\eureka-dc01\fileshare1 /user:user1 Password3355!
        - Credential: net use h: \\eureka-dc01\fileshare1\accounting /user:userfoo Password5!
```