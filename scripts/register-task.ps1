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

$days = ($Day | ForEach-Object { [System.DayOfWeek]$_ }) -join ','
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $days -At $Time

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
    -Description "Schwab OAuth refresh ($($Day -join '/') $Time local) - schwab-refresh" `
    -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
    -Force | Out-Null

$t = Get-ScheduledTask -TaskName $TaskName
$i = Get-ScheduledTaskInfo -TaskName $TaskName
"TaskName  : $($t.TaskName)"
"State     : $($t.State)"
"Action    : $($t.Actions[0].Execute)  (start in $($t.Actions[0].WorkingDirectory))"
"Trigger   : $($t.Triggers[0].StartBoundary)  days=$($t.Triggers[0].DaysOfWeek)"
"MissedRun : $($t.Settings.StartWhenAvailable)"
"NextRun   : $($i.NextRunTime)"
"LastResult: $($i.LastTaskResult)"
