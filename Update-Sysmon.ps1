function Update-Sysmon
{
<#
.SYNOPSIS
    This function can install, uninstall, and update Sysmon. It will detect 
if the Sysmon service exists and validate the file hash against the version 
from the specified directory before choosing to install or update the Sysmon 
configuration. If the hashes do not match, it will uninstall the current 
version and install the version from the $RunDir. This is designed to be run 
as a computer startup script or a daily system task without any user 
interaction.

    Author: Thomas Connell

.DESCRIPTION
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
    PS C:\> Update-Sysmon -RunDir "C:\Installs\Sysmon" -ConfigFile "sysmonconfig-export.xml" -Verbose
    - Installs Sysmon using files in the specified directory and uses a specific config file name
#>
	param
	(
		[Parameter(Position = 0)]
        [string]
		$RunDir = $PSScriptRoot,
		[Parameter(Position = 1)]
        [string]
        $ConfigFile = "sysmonconfig-export.xml",
        [switch]
        $Uninstall
	)

    function Uninstall-Sysmon
    {
        if (Test-Path "C:\Windows\Sysmon.exe")
        {
            Write-Verbose "Uninstalling Sysmon from $ENV:COMPUTERNAME..."
            & "C:\Windows\Sysmon.exe" -u
        }
        else
        {
            Write-Verbose "Sysmon does not appear to be installed!"
        }
    }

    function Install-Sysmon
    {
        if ([Environment]::Is64BitOperatingSystem)
        {
            Write-Verbose "Installing 64-bit Sysmon..."
            & "$RunDir\Sysmon64.exe" -accepteula -i "$RunDir\$ConfigFile"
        }
        else
        {
            Write-Verbose "Installing 32-bit Sysmon..."
            & "$RunDir\Sysmon.exe" -accepteula -i "$RunDir\$ConfigFile"
        }
    }

    function Validate-Sysmon
    {
        if (Test-Path "C:\Windows\Sysmon.exe")
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
            Write-Verbose "Sysmon does not appear to be installed!"
        }
    }

    function Apply-SysmonConfig
    {
        Write-Verbose "Applying Sysmon configuration: $RunDir\$ConfigFile"
        if ([Environment]::Is64BitOperatingSystem)
        {
            & "$RunDir\Sysmon64.exe" -accepteula -c "$RunDir\$ConfigFile"
        }
        else
        {
            & "$RunDir\Sysmon.exe" -accepteula -c "$RunDir\$ConfigFile"
        }
    }

    if ($Uninstall)
    {
        Uninstall-Sysmon
        break
    }

    if ((Test-Path "$RunDir\Sysmon64.exe") -and (Test-Path "$RunDir\Sysmon.exe") -and (Test-Path "$RunDir\$ConfigFile"))
    { #All required files are present
        if ((Get-Service Sysmon -ErrorAction SilentlyContinue).Name -eq "Sysmon")
        {   #Sysmon service exists, validate hash
            if (Validate-Sysmon)
            {   #Re-apply configuration
                Apply-SysmonConfig
            }
            else
            {
                Write-Verbose "Local Sysmon hash does *not* match source file hash..."
                Uninstall-Sysmon
                Start-Sleep -Seconds 5
                Install-Sysmon
            }
        }
        else
        {   #Sysmon service is missing, install it!
            Install-Sysmon
        }
    }
    else
    {
        Write-Error "Required files are missing from $RunDir"
    }
}