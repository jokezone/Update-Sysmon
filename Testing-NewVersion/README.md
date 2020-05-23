# Update-Sysmon Testing-NewVersion Directory
This optional folder is meant to contain a copy of your production deployment files (Update-Sysmon.ps1, Sysmon binaries in x86/x64 sub-folders, and configurations). It allows you to test new versions of the Update-Sysmon function, new Sysmon binaries, and new configuration files on a group of domain computers before applying to production. This is configurable within the Update-SysmonDomainLauncher.ps1 script.

Updating the files in this directory will allow you to observe the behavior on a subset of test computers.

Once testing has been completed, use Update-SysmonDeployment.ps1 to backup and synchronize the changes with the production deployment and Testing-CurrentVersion folders.