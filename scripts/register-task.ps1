<#
.SYNOPSIS
    Register the "SchwabRefresh" scheduled task (idempotent).

.DESCRIPTION
    Wraps refresh.cmd in a Task Scheduler job that runs in the interactive
    session (session-0 Chrome is unreliable), starts missed runs, ignores
    overlapping runs, and restarts twice on failure.

    Defaults to weekly on Friday at 15:00 local time. Pass -Day (or several
    days) if a 7-day interval puts the run right on the refresh token's expiry
    boundary — e.g. a mid-week safety run:

        .\register-task.ps1 -Day Tuesday,Friday

.EXAMPLE
    .\register-task.ps1
    .\register-task.ps1 -Day Tuesday,Friday -Time 15:00
#>
param(
    [string[]]$Day = @('Friday'),
    [string]$Time = '15:00',
    [string]$TaskName = 'SchwabRefresh'
)

$ErrorActionPreference = 'Stop'

$proj = Split-Path -Parent $PSScriptRoot
$cmd = Join-Path $proj 'refresh.cmd'
if (-not (Test-Path $cmd)) { throw "Missing $cmd" }

$action = New-ScheduledTaskAction -Execute $cmd -WorkingDirectory $proj

# `-Day Tuesday,Friday` arrives as two strings from an interactive prompt but as
# the single string "Tuesday,Friday" through -File or a wrapper script, so split
# on commas either way.
$dayList = @(
    $Day | ForEach-Object { $_ -split ',' } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
)
if (-not $dayList) { throw "-Day needs at least one day name (e.g. Friday)." }
$dow = [System.DayOfWeek[]]($dayList | ForEach-Object { [System.DayOfWeek]$_ })
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $dow -At $Time

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 20) `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 10) `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries

# Interactive + Limited: no elevation, and Chrome runs where it works.
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName `
    -Description "Schwab OAuth refresh ($($dayList -join '/') $Time local) - schwab-refresh" `
    -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
    -Force | Out-Null

$t = Get-ScheduledTask -TaskName $TaskName
$i = Get-ScheduledTaskInfo -TaskName $TaskName

# Read the days back off the saved trigger rather than echoing what we asked
# for: that is the field Task Scheduler will actually honour.
$mask = [int]$t.Triggers[0].DaysOfWeek
# DaysOfWeek is a 1-based bitmask (Sunday = 1, Monday = 2, ... Saturday = 64),
# not the numeric value of System.DayOfWeek.
$savedDays = @('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday') |
    Where-Object { $mask -band (1 -shl [int][System.DayOfWeek]$_) }

"TaskName  : $($t.TaskName)"
"State     : $($t.State)"
"Action    : $($t.Actions[0].Execute)  (start in $($t.Actions[0].WorkingDirectory))"
"Trigger   : $($t.Triggers[0].CimClass.CimClassName)  $($t.Triggers[0].StartBoundary)  days=$($savedDays -join ',') (mask $mask)"
"MissedRun : $($t.Settings.StartWhenAvailable)"
"NextRun   : $($i.NextRunTime)"
"LastResult: $($i.LastTaskResult)"
