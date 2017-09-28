function Update-Sysmon
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

    $LogFile = $env:TEMP + "\Update-Sysmon-Log.txt"
    Get-ChildItem $LogFile | Where-Object Length -gt 1024000 | Remove-Item -Confirm:$false
    Start-Transcript $LogFile -Append

    function Uninstall-Sysmon
    {
        if ((Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon") -or (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv"))
        {
            Write-Verbose "$(Get-Date): Uninstalling Sysmon from $ENV:COMPUTERNAME..."
            #& "C:\Windows\Sysmon.exe" -u #Causes memory_corruption BUGCHECK_STR 0x1a_2102 on some systems
            Write-Verbose "$(Get-Date): Removing Sysmon service registry keys - Sysmon will continue to run in memory"
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv" -Recurse -Force -ErrorAction SilentlyContinue

            if ((Test-Path "C:\Windows\Sysmon.exe") -or (Test-Path "C:\Windows\SysmonDrv.sys"))
            {   #Schedule Sysmon files to delete at next reboot
                try
                {   #Append to existing PendingFileRenameOperations registry value to delete Sysmon files at next reboot
                    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" | Select-Object -ExpandProperty "PendingFileRenameOperations" -ErrorAction Stop | Out-Null
                    Write-Verbose "$(Get-Date): Updating existing PendingFileRenameOperations registry value to delete Sysmon files at next reboot."
                    $values = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations").PendingFileRenameOperations
                    $values += "\??\C:\Windows\Sysmon.exe","","\??\C:\Windows\SysmonDrv.sys",""
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "PendingFileRenameOperations" $values
                }
                catch
                {   #Create PendingFileRenameOperations registry value to delete Sysmon files at next reboot
                    Write-Verbose "$(Get-Date): Creating PendingFileRenameOperations registry value to delete Sysmon files at next reboot."
                    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" `
                    -Value "\??\C:\Windows\Sysmon.exe","","\??\C:\Windows\SysmonDrv.sys","" `
                    -PropertyType MultiString -Force | Out-Null
                }
            }
            else
            {
                Write-Verbose "$(Get-Date): Unable to schedule Sysmon files to delete at next reboot becuase they do not exist."
            }
        }
        else
        {
            Write-Verbose "$(Get-Date): Unable to uninstall because Sysmon/SysmonDrv service registry keys are missing. Try running Sysmon.exe -u or reboot and try again."
        }
    }

    function Install-Sysmon([string]$RunDir,[string]$ConfigFile)
    {
        if (-not((Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon") -and (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv") -and (Get-Process -Name "Sysmon")))
        {   #Verify service registry keys and process are not present before attempting an install
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
            if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon")
            {
                Write-Verbose "$(Get-Date): Sysmon installed - Configuration file is being hashed for the first time."
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon" -Name "ConfigFileHash" `
                -Value (Get-FileHash -Path "$RunDir\$ConfigFile" -Algorithm SHA256).Hash `
                -PropertyType STRING -Force | Out-Null
            }
            else
            {
                Write-Verbose "$(Get-Date): Sysmon install failed."
            }
        }
        else
        {
            Write-Verbose "$(Get-Date): Unable to install because Sysmon services or process are present. Please reboot and try again."
        }
    }

    function Validate-Sysmon([string]$RunDir)
    {
        if ((Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon") -and (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv"))
        {
            if ([Environment]::Is64BitOperatingSystem)
            {   #64-bit validation
                if ((Get-FileHash -Path "C:\Windows\Sysmon.exe" -Algorithm SHA256).Hash -eq ((Get-FileHash -Path $RunDir\Sysmon64.exe -Algorithm SHA256).Hash))
                {
                    return $true
                }
                else
                {
                    Write-Verbose "$(Get-Date): Validation failed because local Sysmon hash does not match source file hash."
                }
            }
            else
            {   #32-bit validation
                if ((Get-FileHash -Path "C:\Windows\Sysmon.exe" -Algorithm SHA256).Hash -eq ((Get-FileHash -Path $RunDir\Sysmon.exe -Algorithm SHA256).Hash))
                {
                    return $true
                }
                else
                {
                    Write-Verbose "$(Get-Date): Validation failed because local Sysmon hash does not match source file hash."
                }
            }
        }
        else
        {
            Write-Verbose "$(Get-Date): Validation failed because Sysmon services are not registered."
        }
    }

    function Apply-SysmonConfig([string]$RunDir,[string]$ConfigFile)
    {
        if ((Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon") -and (Get-Process -Name "Sysmon" -ErrorAction SilentlyContinue))
        {
            try
            {
                Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon" | Select-Object -ExpandProperty "ConfigFileHash" -ErrorAction Stop | Out-Null
                if ((Get-FileHash -Path "$RunDir\$ConfigFile" -Algorithm SHA256).Hash -ne (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon" | Select-Object -ExpandProperty "ConfigFileHash"))
                {
                    Write-Verbose "$(Get-Date): Configuration file hash has changed, applying Sysmon configuration: $RunDir\$ConfigFile"
                    & "C:\Windows\Sysmon.exe" -accepteula -c "$RunDir\$ConfigFile"
                    Write-Verbose "$(Get-Date): Updating configuration file hash in local registry"
                    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon" -Name "ConfigFileHash" `
                    -Value (Get-FileHash -Path "$RunDir\$ConfigFile" -Algorithm SHA256).Hash `
                    -PropertyType STRING -Force | Out-Null
                }
            }
            catch
            {
                Write-Verbose "$(Get-Date): Configuration file hash not found, applying Sysmon configuration: $RunDir\$ConfigFile"
                & "C:\Windows\Sysmon.exe" -accepteula -c "$RunDir\$ConfigFile"
                Write-Verbose "$(Get-Date): Writing configuration file hash to local registry."
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon" -Name "ConfigFileHash" `
                -Value (Get-FileHash -Path "$RunDir\$ConfigFile" -Algorithm SHA256).Hash `
                -PropertyType STRING -Force | Out-Null
            }
        }
        else
        {
            Write-Verbose "$(Get-Date): Unable to apply configuration because Sysmon registry key or process are not present"
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
    {   #All required files are present
        if ((Get-Service -Name Sysmon,SysmonDrv -ErrorAction SilentlyContinue).Name -match "Sysmon")
        {   #Sysmon service exists
            if (Validate-Sysmon -RunDir $RunDir)
            {   #Local Sysmon file hash matches source file hash
                #Start Sysmon services if they are stopped
                Get-Service -Name Sysmon,SysmonDrv | Where-Object Status -eq "Stopped" | Start-Service
                Apply-SysmonConfig -RunDir $RunDir -ConfigFile $ConfigFile
            }
            else
            {   #Local Sysmon file hash does not match source file hash
                Uninstall-Sysmon
            }
        }
        else
        {   #Sysmon service is missing, install it!
            Install-Sysmon -RunDir $RunDir -ConfigFile $ConfigFile
        }
    }
    else
    {
        Write-Error "Required Sysmon installation files are missing from $RunDir"
    }
    Stop-Transcript
}