if (Get-Module -Name 'PSPublishModule' -ListAvailable) { 
    Write-Information 'PSPublishModule is installed.'
} else {
    Write-Information 'PSPublishModule is not installed. Attempting installation.'
    try {
        Install-Module -Name Pester -AllowClobber -Scope CurrentUser -SkipPublisherCheck -Force
        Install-Module -Name PSPublishModule -AllowClobber -Scope CurrentUser -Force
    }
    catch {
        Write-Error 'PSPublishModule installation failed.'
    }
}

Import-Module -Name PSPublishModule -Force

Build-Module -ModuleName 'ScriptSentry' {
    # Usual defaults as per standard module
    $Manifest = [ordered] @{
        ModuleVersion        = '0.1'
        CompatiblePSEditions = @('Desktop', 'Core')
        GUID                 = 'e1cd2b55-3b4f-41bd-a168-40db41e34349'
        Author               = 'Spencer Alessi'
        Copyright            = "(c) 2023 - $((Get-Date).Year). All rights reserved."
        Description          = 'ScriptSentry finds misconfigured and dangerous logon scripts.'
        PowerShellVersion    = '5.1'
        Tags                 = @('Windows', 'ScriptSentry', 'netlogon', 'logon script', 'Active Directory')
    }
    New-ConfigurationManifest @Manifest

    # Add standard module dependencies (directly, but can be used with loop as well)
    #New-ConfigurationModule -Type RequiredModule -Name 'PSSharedGoods' -Guid 'Auto' -Version 'Latest'

    # Add external module dependencies, using loop for simplicity
    # those modules are not available in PowerShellGallery so user has to have them installed
    $ExternalModules = @(
        # Required RSAT AD module
        'ActiveDirectory'
        'ServerManager'
        # those modules are builtin in PowerShell so no need to install them
        # could as well be ignored with New-ConfigurationModuleSkip
        'Microsoft.PowerShell.Utility'
        'Microsoft.PowerShell.LocalAccounts',
        'Microsoft.PowerShell.Utility'
        'Microsoft.PowerShell.Management'
        'Microsoft.PowerShell.Security'
        'CimCmdlets'
        'Dism'
    )
    foreach ($Module in $ExternalModules) {
        New-ConfigurationModule -Type ExternalModule -Name $Module
    }

    New-ConfigurationModuleSkip -IgnoreFunctionName 'Clear-Host'

    $ConfigurationFormat = [ordered] @{
        RemoveComments                              = $false

        PlaceOpenBraceEnable                        = $true
        PlaceOpenBraceOnSameLine                    = $true
        PlaceOpenBraceNewLineAfter                  = $true
        PlaceOpenBraceIgnoreOneLineBlock            = $false

        PlaceCloseBraceEnable                       = $true
        PlaceCloseBraceNewLineAfter                 = $true
        PlaceCloseBraceIgnoreOneLineBlock           = $false
        PlaceCloseBraceNoEmptyLineBefore            = $true

        UseConsistentIndentationEnable              = $true
        UseConsistentIndentationKind                = 'space'
        UseConsistentIndentationPipelineIndentation = 'IncreaseIndentationAfterEveryPipeline'
        UseConsistentIndentationIndentationSize     = 4

        UseConsistentWhitespaceEnable               = $true
        UseConsistentWhitespaceCheckInnerBrace      = $true
        UseConsistentWhitespaceCheckOpenBrace       = $true
        UseConsistentWhitespaceCheckOpenParen       = $true
        UseConsistentWhitespaceCheckOperator        = $true
        UseConsistentWhitespaceCheckPipe            = $true
        UseConsistentWhitespaceCheckSeparator       = $true

        AlignAssignmentStatementEnable              = $true
        AlignAssignmentStatementCheckHashtable      = $true

        UseCorrectCasingEnable                      = $true
    }
    # format PSD1 and PSM1 files when merging into a single file
    # enable formatting is not required as Configuration is provided
    New-ConfigurationFormat -ApplyTo 'OnMergePSM1', 'OnMergePSD1' -Sort None @ConfigurationFormat
    # format PSD1 and PSM1 files within the module
    # enable formatting is required to make sure that formatting is applied (with default settings)
    New-ConfigurationFormat -ApplyTo 'DefaultPSD1', 'DefaultPSM1' -EnableFormatting -Sort None
    # when creating PSD1 use special style without comments and with only required parameters
    New-ConfigurationFormat -ApplyTo 'DefaultPSD1', 'OnMergePSD1' -PSD1Style 'Minimal'

    # configuration for documentation, at the same time it enables documentation processing
    New-ConfigurationDocumentation -Enable:$false -StartClean -UpdateWhenNew -PathReadme 'Docs\Readme.md' -Path 'Docs'

    New-ConfigurationImportModule -ImportSelf -ImportRequiredModules

    New-ConfigurationBuild -Enable:$true -SignModule:$false -DeleteTargetModuleBeforeBuild -MergeModuleOnBuild -UseWildcardForFunctions

    # New-ConfigurationArtefact -Type Unpacked -Enable -Path "$PSScriptRoot\..\Artefacts\Unpacked"
    # New-ConfigurationArtefact -Type Packed -Enable -Path "$PSScriptRoot\..\Artefacts\Packed" -IncludeTagName

    # New-ConfigurationArtefact -Type Script -Enable -Path "$PSScriptRoot\..\Script" {
    #     Invoke-ModuleBuilder
    # }

    # global options for publishing to github/psgallery
    #New-ConfigurationPublish -Type PowerShellGallery -FilePath 'C:\Support\Important\PowerShellGalleryAPI.txt' -Enabled:$false
    #New-ConfigurationPublish -Type GitHub -FilePath 'C:\Support\Important\GitHubAPI.txt' -UserName 'CompanyName' -Enabled:$false
}
