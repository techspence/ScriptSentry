function Get-Prerequisites {
    # Check if ActiveDirectory PowerShell module is available, and attempt to install if not found
    if (-not(Get-Module -Name 'ActiveDirectory' -ListAvailable)) {
        $OS = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
        # 1 - workstation, 2 - domain controller, 3 - non-dc server
        if ($OS -gt 1) {
            # Attempt to install ActiveDirectory PowerShell module for Windows Server OSes, works with Windows Server 2012 R2 through Windows Server 2022
            Install-WindowsFeature -Name RSAT-AD-PowerShell
        } else {
            # Attempt to install ActiveDirectory PowerShell module for Windows Desktop OSes
            Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online
        }
    }
    }