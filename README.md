# Update-Sysmon Overview
This function was created to aid in the deployment/maintenance of the Sysmon service on a large number of computers. System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log.

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

The Update-Sysmon function can be deployed as a computer startup script or a scheduled system task to deploy the Sysmon service on all domain Windows endpoints without any user interaction. An hourly scheduled task is preferred because it will ensure the Sysmon service is always running. Host the function and Sysmon binaries in a share all domain computers can access (such as NETLOGON).

The Update-SysmonDomainLauncher.ps1 script can be used to set the Update-Sysmon parameters based on the domain computer account role and group membership. This allows you to deploy a single policy to all systems while applying Sysmon configurations tailored to the Operating System role (workstation, member server, or domain controller). You can also apply custom settings based on AD security group membership. This is useful for re-directing a group of test computers to a Sysmon deployment share containing a new version of the Sysmon utility along with configuration files for that version.

### Deployment Folder Structure ###

At a minimum, the function expects x86/x64 sub-folders in the script running directory containing the appropriate Sysmon installation binary. Aside from that, you can place the configuration files anywhere you want. This can be as basic or over engineered as you wish.

This folder structure works best when using the Update-SysmonDomainLauncher.ps1 script:

    .
    ├── x64
    │   ├── Sysmon.exe
    ├── x86
    │   ├── Sysmon.exe
    ├── Config
    │   ├── sysmonconfig-domaincontroller-production.xml
    │   ├── sysmonconfig-memberserver-production.xml
    │   ├── sysmonconfig-workstation-production.xml
    │   ├── sysmonconfig-verbose-production.xml
    └── Update-Sysmon.ps1
    └── Update-SysmonDomainLauncher.ps1
    └── ...

A Testing-CurrentVersion domain group and deployment folder can be used for testing configuration changes against the current production binary version of Sysmon. A Testing-NewVersion domain group and deployment folder can be used for testing upgrades to a new binary version of Sysmon and configuration. It is useful to re-direct the transcript logging of test systems to a file share in order to easily review test results. Once testing has completed, the files in the root production folder are overwritten with the validated files in the test folder.

### Deployment Resources ###

Your Sysmon deployment will not be successful without two very important resources:

#### 1) The Sysmon x86/x64 installation files ####

* https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

#### 2) Sysmon configurations tailored to each OS role in your environment ####

* https://github.com/SwiftOnSecurity/sysmon-config
* https://github.com/olafhartong/sysmon-modular
