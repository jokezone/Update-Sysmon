# Update-Sysmon
This function was created to aide in the deployment/maintenance of the Sysmon service on a large number of computers. System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log.

The Update-Sysmon function can install, uninstall, and update Sysmon. It will detect if the Sysmon service exists and validate the file hash against the version from the specified directory before choosing to install or update the Sysmon binary and/or configuration. You must stage the Sysmon installation files in x86/x64 sub-folders of the script running directory. Each filename must match the name you choose for the service (default=Sysmon).

## Usage ##
### Install Method #1 ###
Installs Sysmon using "Sysmon.exe" found in the script running directory x86/x64 sub-folders. If Sysmon is already installed, the configuration will be checked for updates.
~~~~
PS C:\> Update-Sysmon -Verbose
~~~~

### Install Method #2 ###
Installs Sysmon using files in the specified directory and uses a specific config file name. Only the configuration is updated if Sysmon is already installed.
~~~~
PS C:\> Update-Sysmon -RunDir "C:\Installs\Sysmon" -ConfigFile "Config\workstation-sysmonconfig.xml" -Verbose
~~~~

### Install Method #3 ###
Installs Sysmon using "StealthService.exe" found in the script running directory x86/x64 sub-folders. The service and running process will be named "StealthService".
~~~~
PS C:\> Update-Sysmon -SvcName "StealthService" -Verbose
~~~~

### Uninstall ###
Forcibly uninstalls Sysmon service named "Sysmon". You may also use the Graceful uninstall method which requires a reboot.
~~~~
PS C:\> Update-Sysmon -Uninstall -SvcName "Sysmon" -UninstallMethod "Force" -Verbose
~~~~

## Domain Deployment ##

The Update-Sysmon function can be deployed as a computer startup script or a scheduled system task without any user interaction. An hourly scheduled task is preferred because it will ensure the Sysmon service is always running. Simply host the function and Sysmon binaries in a share all domain computers can access (such as NETLOGON).

The Update-SysmonDomainLauncher.ps1 script can be used to set the Update-Sysmon parameters based on the domain computer account role and group membership. This allows you to deploy a single policy to all systems while applying Sysmon configurations tailored to the Operating System type (workstation, member server, or domain controller). You can also apply custom settings based on AD security group membership. This is useful for re-directing a group of test computers to a Sysmon deployment share containing a new version of the Sysmon utility. After sufficient testing of a new version, just copy the tested files into the production deployment folder for domain clients to update to the new version.
