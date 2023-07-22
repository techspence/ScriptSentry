# ScriptSentry
ScriptSentry finds misconfigured and dangerous logon scripts.

### Installing
```PowerShell
git clone https://github.com/techspence/ScriptSentry
.\Build\Build-Module.ps1
Import-Module ScriptSentry.psm1
```

### Running
```PowerShell
# Run ScriptSentry and display results to the console
Invoke-ScriptSentry

# Run ScriptSentry and save results to a file
Invoke-ScriptSentry | Out-File c:\temp\ScriptSentry.txt
```