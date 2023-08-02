@{
    AliasesToExport      = @('*')
    Author               = 'Spencer Alessi'
    CmdletsToExport      = @()
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2023 - 2023. All rights reserved.'
    Description          = 'ScriptSentry finds misconfigured and dangerous logon scripts.'
    FunctionsToExport    = @('*')
    GUID                 = 'e1cd2b55-3b4f-41bd-a168-40db41e34349'
    ModuleVersion        = '0.2_dev'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            Tags                       = @('Windows', 'ScriptSentry', 'netlogon', 'logon script', 'Active Directory')
            ExternalModuleDependencies = @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security')
        }
    }
    RequiredModules      = @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security')
    RootModule           = 'ScriptSentry.psm1'
}