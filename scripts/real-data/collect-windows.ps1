# Exports this Windows host's System, Application and PowerShell Operational events as NDJSON for
# `scripts/real-data/run.sh`: one flat JSON object per event, the record's own fields plus each
# named EventData item at the top level, in Sigma's field names.
#
#   powershell -File scripts/real-data/collect-windows.ps1 -Out \\wsl.localhost\Ubuntu-24.04\home\<you>\.cache\sluice-realdata\windows
#
# The events are real and personal: keep -Out outside the repository.
param(
    [Parameter(Mandatory = $true)][string]$Out,
    [int]$MaxEvents = 20000
)
$ErrorActionPreference = 'Stop'

function Convert-Event($record) {
    $event = [ordered]@{
        '@timestamp'    = $record.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        'Channel'       = $record.LogName
        'Computer'      = $record.MachineName
        'EventID'       = $record.Id
        'Keywords'      = '0x{0:x16}' -f $record.Keywords
        'Level'         = [int]$record.Level
        'ProcessID'     = $record.ProcessId
        'Provider_Name' = $record.ProviderName
        'Task'          = $record.Task
        'ThreadID'      = $record.ThreadId
    }
    $message = $null
    try { $message = $record.FormatDescription() } catch { }
    if ($message) { $event['Message'] = $message.Trim() }
    $xml = [xml]$record.ToXml()
    foreach ($data in @($xml.Event.EventData.Data)) {
        if ($data -is [System.Xml.XmlElement] -and $data.Name -and -not $event.Contains($data.Name)) {
            $event[$data.Name] = [string]$data.InnerText
        }
    }
    $event
}

function Export-Log([string]$log, [string]$file, [scriptblock]$keep) {
    $lines = New-Object System.Collections.Generic.List[string]
    $records = Get-WinEvent -LogName $log -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
    foreach ($record in $records) {
        if (& $keep $record) {
            $lines.Add((Convert-Event $record | ConvertTo-Json -Compress -Depth 3))
        }
    }
    $path = Join-Path $Out $file
    [System.IO.File]::WriteAllLines($path, $lines, (New-Object System.Text.UTF8Encoding($false)))
    "{0,-22} {1,7} events" -f $file, $lines.Count
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$all = { $true }
Export-Log 'System' 'system.ndjson' $all
Export-Log 'Application' 'application.ndjson' $all
$ps = 'Microsoft-Windows-PowerShell/Operational'
Export-Log $ps 'ps-script.ndjson' { param($r) $r.Id -eq 4104 }
Export-Log $ps 'ps-other.ndjson' { param($r) $r.Id -ne 4104 }
