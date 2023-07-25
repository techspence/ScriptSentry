# ScriptSentry
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