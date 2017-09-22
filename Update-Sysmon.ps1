﻿function Update-Sysmon
{
<#
.SYNOPSIS
    This function can install, uninstall, and update Sysmon. It will detect 
if the Sysmon service exists and validate the file hash against the version 
from the specified directory before choosing to install or update the Sysmon 
configuration. If the hashes do not match, it will uninstall the current 
version and install the version from the $RunDir.

    Author: Thomas Connell

.DESCRIPTION
    This function was created to aide in the deployment/maintenance of 
the Sysmon service to a large number of computers. It is designed to 
be run as a computer startup script or a daily system task without any 
user interaction.

    System Monitor (Sysmon) is a Windows system service and device driver 
that, once installed on a system, remains resident across system reboots to 
monitor and log system activity to the Windows event log. It provides 
detailed information about process creations, network connections, and 
changes to file creation time.

.LINK
    Sysmon documentation:
    https://technet.microsoft.com/en-us/sysinternals/dn798348
    Community supported Sysmon configuration:
    https://github.com/SwiftOnSecurity/sysmon-config

.EXAMPLE
    PS C:\> Update-Sysmon -Verbose
    - Installs Sysmon using source files found in the script running directory
.EXAMPLE
    PS C:\> Update-Sysmon -Uninstall -Verbose
    - Uninstalls Sysmon
.EXAMPLE
    PS C:\> Update-Sysmon -RunDir "C:\Installs\Sysmon" -ConfigFile "Config\workstation-sysmonconfig.xml" -Verbose
    - Installs Sysmon using files in the specified directory and uses a specific config file name
    - Only the configuration is updated if Sysmon is already installed
.EXAMPLE
    PS C:\> PowerShell.exe -Command {. "\\Path\To\Sysmon\Update-Sysmon.ps1";Update-Sysmon}
    - Method to load and execute function from a file share without any user interaction
#>
	param
	(
        [Parameter(Position = 0)]
        [string]
        $RunDir = $PSScriptRoot,
        [Parameter(Position = 1)]
        [string]
        $ConfigFile = "auto-select",
        [switch]
        $Uninstall
	)

    function Uninstall-Sysmon
    {
        if ((Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon") -and (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv"))
        #if ((Test-Path "C:\Windows\Sysmon.exe") -and (Test-Path "C:\Windows\SysmonDrv.sys"))
        {
            Write-Verbose "$(Get-Date): Uninstalling Sysmon from $ENV:COMPUTERNAME..."
            #& "C:\Windows\Sysmon.exe" -u #Causes memory_corruption BUGCHECK_STR 0x1a_2102 on some systems
            Write-Verbose "$(Get-Date): Removing Sysmon service registry keys - Sysmon will continue to run until the next reboot"
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon" -Recurse -Force
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv" -Recurse -Force
        }
        else
        {
            Write-Verbose "$(Get-Date): Unable to uninstall - Sysmon does not appear to be installed!"
        }
    }

    function Install-Sysmon
    {
        if (-not((Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon") -and (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv") -and (Get-Process -Name "Sysmon")))
        { #Verify service registry keys and process are not present before attempting an install
            if ([Environment]::Is64BitOperatingSystem)
            {
                Write-Verbose "$(Get-Date): Installing 64-bit Sysmon..."
                & "$RunDir\Sysmon64.exe" -accepteula -i "$RunDir\$ConfigFile"
            }
            else
            {
                Write-Verbose "$(Get-Date): Installing 32-bit Sysmon..."
                & "$RunDir\Sysmon.exe" -accepteula -i "$RunDir\$ConfigFile"
            }
        }
        else
        {
            Write-Verbose "$(Get-Date): Unable to install because Sysmon services or process are present. Please reboot and try again."
        }
    }

    function Validate-Sysmon
    {
        if ((Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon") -and (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv"))
        {
            if ([Environment]::Is64BitOperatingSystem)
            {   # 64-bit validation
                if ((Get-FileHash -Path "C:\Windows\Sysmon.exe" -Algorithm SHA256).Hash -eq ((Get-FileHash -Path $RunDir\Sysmon64.exe -Algorithm SHA256).Hash))
                {
                    return $true
                }
            }
            else
            {   # 32-bit validation
                if ((Get-FileHash -Path "C:\Windows\Sysmon.exe" -Algorithm SHA256).Hash -eq ((Get-FileHash -Path $RunDir\Sysmon.exe -Algorithm SHA256).Hash))
                {
                    return $true
                }
            }
        }
        else
        {
            Write-Verbose "$(Get-Date): Validation failed - Sysmon does not appear to be installed!"
        }
    }

    function Apply-SysmonConfig
    {
        if ((Test-Path "C:\Windows\Sysmon.exe") -and (Test-Path "C:\Windows\SysmonDrv.sys") -and (Get-Process -Name "Sysmon"))
        {
            Write-Verbose "$(Get-Date): Applying Sysmon configuration: $RunDir\$ConfigFile"
            & "C:\Windows\Sysmon.exe" -accepteula -c "$RunDir\$ConfigFile"

            if ((Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue).Status -eq "Stopped")
            { #Sysmon service was stopped and needs to be started
                Write-Verbose "$(Get-Date): Starting Sysmon service..."
                Start-Service -Name "Sysmon"
            }
        }
        else
        {
            Write-Verbose "$(Get-Date): Unable to apply configuration - Sysmon does not appear to be installed or running!"
        }
    }

    if ($Uninstall)
    {
        Uninstall-Sysmon
        break
    }

    if ($ConfigFile -eq "auto-select")
    {
        <# Select configuration file based on OS type
        0 = Standalone Workstation
        1 = Member Workstation
        2 = Standalone Server
        3 = Member Server
        4 = Backup Domain Controller
        5 = Primary Domain Controller
        #>
        $Role = (Get-WmiObject Win32_ComputerSystem).DomainRole
        if ($Role -eq 1) {$ConfigFile = "Config\sysmonconfig-workstation2-production.xml"}
        if ($Role -eq 3) {$ConfigFile = "Config\sysmonconfig-memberserver2-production.xml"}
        if ($Role -ge 4) {$ConfigFile = "Config\sysmonconfig-domaincontroller2-production.xml"}
    }

    Write-Verbose "$(Get-Date): Script RunDir: $RunDir"
    Write-Verbose "$(Get-Date): Configuration file: $ConfigFile"

    if ((Test-Path "$RunDir\Sysmon64.exe") -and (Test-Path "$RunDir\Sysmon.exe") -and (Test-Path "$RunDir\$ConfigFile"))
    { #All required files are present
        if ((Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue).Name -eq "Sysmon")
        {   #Sysmon service exists, validate hash
            if (Validate-Sysmon)
            {   #Re-apply configuration
                Apply-SysmonConfig
            }
            else
            {
                Write-Verbose "$(Get-Date): Local Sysmon hash does *not* match source file hash. Sysmon will be re-installed."
                Uninstall-Sysmon
            }
        }
        else
        {   #Sysmon service is missing, install it!
            Install-Sysmon
        }
    }
    else
    {
        Write-Error "Required Sysmon installation files are missing from $RunDir"
    }
}