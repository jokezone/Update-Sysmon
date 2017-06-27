. .\Get-SysmonEventData.ps1

foreach ($ID in (1,2,3,5,6,7,8,9,10,11,12,13,14,15,16,17,18,255))
{
    $events = @()
    $events = Get-SysMonEventData -EventId $ID -EndTime (Get-Date) -StartTime (Get-Date).AddDays(-3) -ErrorAction SilentlyContinue
    if ($events.count -ne "0"){$events | Export-Csv -NoTypeInformation -Path .\Sysmon_$($ID)_$($events[0].EventType)_$($events.count)_Events.csv}
    Write-Host "$($events.count) Sysmon Event ID $ID events found."
}