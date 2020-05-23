<#
.SYNOPSIS
    This script will backup the production Sysmon configuration before replacing it with a tested version.
    Author: Thomas Connell
#>

$ProductionDir = "\\PATH\TO\PRODUCTION\Sysmon"
$CurrentVersionTestDir = "Testing-CurrentVersion"
$NewVersionTestDir = "Testing-NewVersion"

function Update-FromCurrentVersion($Type)
{
    #Created configuration backup directory
    New-Item "$ProductionDir\Config\Backups" -ItemType Directory -Force | Out-Null

    if (($Type -eq "workstation") -or ($Type -eq "memberserver") -or ($Type -eq "domaincontroller"))
    {
        Write-Host "Processing $Type configuration"

        $ProductionFile = "$ProductionDir\Config\sysmonconfig-$Type-production.xml"
        $CurrentVersionFile = "$ProductionDir\$CurrentVersionTestDir\Config\sysmonconfig-$Type-testing.xml"

        if (((Get-ChildItem -Path $ProductionFile -ErrorAction SilentlyContinue).LastWriteTime) -ne ((Get-ChildItem -Path $CurrentVersionFile -ErrorAction SilentlyContinue).LastWriteTime))
        {
            if (Test-Path $ProductionFile)
            { #Backup production configuration
                $ProdDate = ((Get-ChildItem -Path $ProductionFile).LastWriteTime).ToString("yyy-MM-dd")
                Copy-Item -Path $ProductionFile -Destination "$ProductionDir\Config\Backups\$ProdDate-sysmonconfig-$Type-production.xml"
                Write-Host -ForegroundColor Green "Production $Type configuration backed up to $ProductionDir\Config\Backups\$ProdDate-sysmonconfig-$Type-production.xml"

                if ((Test-Path $CurrentVersionFile) -and (Test-Path "$ProductionDir\Config\Backups\$ProdDate-sysmonconfig-$Type-production.xml"))
                { #Write test configuration to production
                    Copy-Item -Path $CurrentVersionFile -Destination $ProductionFile
                    Write-Host -ForegroundColor Green "Testing $Type configuration dated $((Get-ChildItem -Path  $CurrentVersionFile).LastWriteTime) written to production"
                }
                Else
                {
                    Write-Host -ForegroundColor Red "Writing $Type test configuration to production failed! Verify $CurrentVersionFile exists."
                }
            }
            Else
            {
                Write-Host -ForegroundColor Red "Backup of $Type production configuration failed! Verify $ProductionFile exists."
            }
        }
        Else
        {
            Write-Host -ForegroundColor Red "There is nothing to do. The $Type test configuration has not changed."
        }
    }
    Else
    {
        Write-Host -ForegroundColor Red "`"$Type`" does not match an approved string"
    }
}

function Update-FromNewVersion()
{
    #Created backup directories
    New-Item "$ProductionDir\Config\Backups" -ItemType Directory -Force | Out-Null
    New-Item "$ProductionDir\x64\Backups" -ItemType Directory -Force | Out-Null
    New-Item "$ProductionDir\x86\Backups" -ItemType Directory -Force | Out-Null

    if (((Get-ChildItem -Path "$ProductionDir\x64\Sysmon.exe" -ErrorAction SilentlyContinue).LastWriteTime) -ne ((Get-ChildItem -Path "$ProductionDir\$NewVersionTestDir\x64\Sysmon.exe" -ErrorAction SilentlyContinue).LastWriteTime))
    {   #Backup production binaries
        $Prod64Date = ((Get-ChildItem -Path "$ProductionDir\x64\Sysmon.exe").LastWriteTime).ToString("yyy-MM-dd")
        $Prod86Date = ((Get-ChildItem -Path "$ProductionDir\x86\Sysmon.exe").LastWriteTime).ToString("yyy-MM-dd")
        Copy-Item -Path "$ProductionDir\x64\Sysmon.exe" -Destination "$ProductionDir\x64\Backups\$Prod64Date-Sysmon.exe"
        Copy-Item -Path "$ProductionDir\x86\Sysmon.exe" -Destination "$ProductionDir\x86\Backups\$Prod86Date-Sysmon.exe"
        Write-Host -ForegroundColor Green "Production Sysmon binaries backed up to the $ProductionDir\x64 -and- x86\Backups folder"

        #Backup production configuration
        Get-ChildItem "$ProductionDir\Config" | Where-Object {$_.PSIsContainer -eq $false} | ForEach {
            $ProdDate = ((Get-ChildItem -Path $_.FullName).LastWriteTime).ToString("yyy-MM-dd")
            Copy-Item -Path $_.FullName -Destination "$ProductionDir\Config\Backups\$ProdDate-$($_.Name)" -Force
            Write-Host -ForegroundColor Green "Production configuration backed up to $ProductionDir\Config\Backups\$ProdDate-$($_.Name)"
        }

        if ((Test-Path "$ProductionDir\$NewVersionTestDir\x64\Sysmon.exe") -and (Test-Path "$ProductionDir\x64\Backups\$Prod64Date-Sysmon.exe"))
        {   #Replace production binaries
            Copy-Item -Path "$ProductionDir\$NewVersionTestDir\x64\Sysmon.exe" -Destination "$ProductionDir\x64\Sysmon.exe"
            Copy-Item -Path "$ProductionDir\$NewVersionTestDir\x86\Sysmon.exe" -Destination "$ProductionDir\x86\Sysmon.exe"
            Write-Host -ForegroundColor Green "Tested Sysmon binaries in the $NewVersionTestDir folder dated $((Get-ChildItem -Path "$ProductionDir\$NewVersionTestDir\x64\Sysmon.exe").LastWriteTime) were written to production"

            #Replace production configuration
            Get-ChildItem "$ProductionDir\$NewVersionTestDir\Config" | Where-Object {$_.PSIsContainer -eq $false} | ForEach {
                Copy-Item -Path $_.FullName -Destination "$ProductionDir\Config\$($_.Name -replace "testing","production")"
                Write-Host -ForegroundColor Green "$ProductionDir\Config\$($_.Name -replace "testing","production"): Production Sysmon configuration replaced with the tested version from the $NewVersionTestDir folder"
            }

            #Replace CurrentVersion files
            Copy-Item -Path "$ProductionDir\$NewVersionTestDir\x64\Sysmon.exe" -Destination "$ProductionDir\$CurrentVersionTestDir\x64\Sysmon.exe"
            Copy-Item -Path "$ProductionDir\$NewVersionTestDir\x86\Sysmon.exe" -Destination "$ProductionDir\$CurrentVersionTestDir\x86\Sysmon.exe"
            Write-Host -ForegroundColor Green "Tested Sysmon binaries in the $NewVersionTestDir folder dated $((Get-ChildItem -Path "$ProductionDir\$NewVersionTestDir\x64\Sysmon.exe").LastWriteTime) were written to $CurrentVersionTestDir"
            Get-ChildItem "$ProductionDir\$NewVersionTestDir\Config" | Where-Object {$_.PSIsContainer -eq $false} | ForEach {
                Copy-Item -Path $_.FullName -Destination "$ProductionDir\$CurrentVersionTestDir\Config\$($_.Name)"
                Write-Host -ForegroundColor Green "$ProductionDir\$CurrentVersionTestDir\Config\$($_.Name): $CurrentVersionTestDir Sysmon configuration replaced with the tested version from the $NewVersionTestDir folder"
            }
        }
        Else
        {
            Write-Host -ForegroundColor Red "Writing tested Sysmon binary to production failed! Verify $ProductionDir\$NewVersionTestDir\x64\Sysmon.exe exists."
        }
    }
    Else
    {
        Write-Host -ForegroundColor Red "There is nothing to do. The NewVersion Sysmon binary has not changed."
    }
}

function Show-Menu
{
    param (
        [string]$Title = 'My Menu'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    
    Write-Host "1: Press '1' to update Workstation Sysmon config from the CurrentVersion folder"
    Write-Host "1: Press '2' to update Member Server Sysmon config from the CurrentVersion folder"
    Write-Host "1: Press '3' to update Domain Controller Sysmon config from the CurrentVersion folder"
    Write-Host "2: Press '4' to update all Sysmon files from the NewVersion folder"
    Write-Host "Q: Press 'Q' to quit."
}

Show-Menu –Title 'Sysmon Update Menu'
 $selection = Read-Host "Please make a selection"
 switch ($selection)
 {
     '1' {
            'You chose to update the production Workstation Sysmon configuration from the CurrentVersion folder'
            Write-Host -nonewline "Continue? (Y/N) "
            $response = Read-Host
            if ( $response -ne "Y" ) { return }
            Update-FromCurrentVersion "workstation"
     } '2' {
            'You chose to update the production Member Server Sysmon configuration from the CurrentVersion folder'
            Write-Host -nonewline "Continue? (Y/N) "
            $response = Read-Host
            if ( $response -ne "Y" ) { return }
            Update-FromCurrentVersion "memberserver"
     } '3' {
            'You chose to update the production Domain Controller Sysmon configuration from the CurrentVersion folder'
            Write-Host -nonewline "Continue? (Y/N) "
            $response = Read-Host
            if ( $response -ne "Y" ) { return }
            Update-FromCurrentVersion "domaincontroller"
     } '4' {
            'You chose to update all production Sysmon binaries and configurations from the NewVersion folder'
            Write-Host -nonewline "Continue? (Y/N) "
            $response = Read-Host
            if ( $response -ne "Y" ) { return }
            Update-FromNewVersion
     } 'q' {
         return
     }
 }
