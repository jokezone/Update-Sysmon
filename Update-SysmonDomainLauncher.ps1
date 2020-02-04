<#
.SYNOPSIS
    This script will set the Update-Sysmon parameters based on the domain computer account role and group membership.
    This allows you to deploy a single policy to all systems while applying Sysmon configurations tailored to the 
    Operating System type (workstation, member server, or domain controller). You can also apply custom settings 
    based on AD security group membership. This is useful for re-directing a group of test computers to a Sysmon 
    deployment share containing a new version of the Sysmon utility along with configuration files for that version.
    Author: Thomas Connell
    Source project: https://github.com/jokezone/Update-Sysmon
#>

$FileShare = "\\FILESERVER\ShareName"
$RunDir = $PSScriptRoot
$LogDir = $env:TEMP
$ConfigFile = $null
$DelayExecution = 10

if ($DelayExecution -gt 0)
{
    $delay = Get-Random -Minimum 1 -Maximum $DelayExecution
    Write-Host "$(Get-Date): Delaying execution for $delay minutes"
    Start-Sleep -Seconds ($delay * 60)
}

try
{
    # Query AD for group membership of computer
    $domainDN = ([ADSI]"").distinguishedName
    $root = [ADSI]"LDAP://$domainDN"
    $search = [adsisearcher]$root
    $Search.Filter = "(&(SamAccountName=$ENV:COMPUTERNAME$))"
    $computer = $Search.FindOne()
    $computerproperties = $computer.Properties
    [array]$groups = $computerproperties.memberof

    # Identify the computer role
    $Role = (Get-WmiObject Win32_ComputerSystem).DomainRole
    if ($Role -eq 1) {$OSType = "workstation"}
    if ($Role -eq 3) {$OSType = "memberserver"}
    if ($Role -ge 4) {$OSType = "domaincontroller"}

    # Set script parameters
    $groupToMatch = "Sysmon-Testing-CurrentVersion"
    if($groups -match $groupToMatch)
    {
        $ConfigFile = "Config\sysmonconfig-$OSType-testing.xml"
        $RunDir = $PSScriptRoot + "\Testing-CurrentVersion"
        $UninstallMethod = "Graceful"
        $LogDir = $FileShare + "\Sysmon-Logs\Testing-CurrentVersion"
    }
    $groupToMatch = "Sysmon-Verbose"
    if($groups -match $groupToMatch)
    {
        $ConfigFile = "Config\sysmonconfig-$OSType-verbose.xml"
        $LogDir = $FileShare + "\Sysmon-Logs\Verbose"
    }
    $groupToMatch = "Sysmon-Testing-NewVersion"
    if($groups -match $groupToMatch)
    {
        $ConfigFile = "Config\sysmonconfig-$OSType-testing.xml"
        $RunDir = $PSScriptRoot + "\Testing-NewVersion"
        $UninstallMethod = "Force"
        $LogDir = $FileShare + "\Sysmon-Logs\Testing-NewVersion"
    }
    if (-not($ConfigFile))
    {
        $ConfigFile = "Config\sysmonconfig-$OSType-production.xml"
        $UninstallMethod = "Graceful"
    }
}
catch
{
    Write-Host "$(Get-Date): Unable to query AD to dynamically set a configuration file."
}

# Run Update-Sysmon using calculated parameters
. "$RunDir\Update-Sysmon.ps1"
Update-Sysmon -RunDir $RunDir -ConfigFile $ConfigFile -UninstallMethod $UninstallMethod -LogDir $LogDir -Verbose
