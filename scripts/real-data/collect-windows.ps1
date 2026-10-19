# Exports this Windows host's events as NDJSON for `scripts/real-data/`.
#
#   -Format sigma (default): System, Application and PowerShell Operational as flat JSON objects
#     in Sigma's field names (each named EventData item at the top level), for `run.sh`.
#   -Format agent: the same channels, or with -Security the Security channel alone (needs an
#     elevated shell), as Vector's `windows_event_log` source emits them: the sample for a Vector
#     that reads the event log itself.
#
#   powershell -File scripts/real-data/collect-windows.ps1 -Out \\wsl.localhost\Ubuntu-24.04\home\<you>\.cache\sluice-realdata\windows
#
# The events are real and personal: keep -Out outside the repository.
param(
    [Parameter(Mandatory = $true)][string]$Out,
    [int]$MaxEvents = 20000,
    [ValidateSet('sigma', 'agent')][string]$Format = 'sigma',
    [switch]$Security
)
$ErrorActionPreference = 'Stop'

function EventData($record) {
    $data = [ordered]@{}
    $xml = [xml]$record.ToXml()
    foreach ($item in @($xml.Event.EventData.Data)) {
        if ($item -is [System.Xml.XmlElement] -and $item.Name -and -not $data.Contains($item.Name)) {
            $data[$item.Name] = [string]$item.InnerText
        }
    }
    $data
}

$titles = @{}

function Message($record) {
    # Security events: Sluice's SecurityEvent shape reads only the first line of the message
    # (`Activity`), the same for every event of an ID, and formatting each message is what makes
    # an export of the Security channel slow. Format it once per provider and ID.
    if ($Security) {
        $key = "$($record.ProviderName)/$($record.Id)"
        if (-not $titles.ContainsKey($key)) {
            try { $text = $record.FormatDescription() } catch { $text = $null }
            $titles[$key] = if ($text) { ($text.Trim() -split "`r?`n")[0] } else { $null }
        }
        return $titles[$key]
    }
    try { $text = $record.FormatDescription() } catch { $text = $null }
    if ($text) { $text.Trim() } else { $null }
}

function Convert-Sigma($record) {
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
    $message = Message $record
    if ($message) { $event['Message'] = $message }
    $data = EventData $record
    foreach ($name in $data.Keys) {
        if (-not $event.Contains($name)) { $event[$name] = $data[$name] }
    }
    $event
}

function Convert-Agent($record) {
    $event = [ordered]@{
        'channel'       = $record.LogName
        'computer'      = $record.MachineName
        'event_data'    = EventData $record
        'event_id'      = $record.Id
        'host'          = $record.MachineName
        'keyword_names' = @($record.KeywordsDisplayNames)
        'keywords'      = '0x{0:x16}' -f $record.Keywords
        'level'         = $record.LevelDisplayName
        'level_value'   = [int]$record.Level
        'process_id'    = $record.ProcessId
        'provider_name' = $record.ProviderName
        'record_id'     = $record.RecordId
        'source_type'   = 'windows_event_log'
        'task'          = $record.Task
        'thread_id'     = $record.ThreadId
        'timestamp'     = $record.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffff00Z')
        'version'       = [int]$record.Version
    }
    $message = Message $record
    if ($message) { $event['message'] = $message }
    if ($record.ActivityId) { $event['activity_id'] = '{' + $record.ActivityId + '}' }
    if ($record.ProviderId) { $event['provider_guid'] = '{' + $record.ProviderId + '}' }
    if ($record.TaskDisplayName) { $event['task_name'] = $record.TaskDisplayName }
    $event
}

function Export-Log([string[]]$logs, [string]$file, [scriptblock]$keep) {
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($log in $logs) {
        $records = Get-WinEvent -LogName $log -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        foreach ($record in $records) {
            if (& $keep $record) {
                $event = if ($Format -eq 'agent') { Convert-Agent $record } else { Convert-Sigma $record }
                $lines.Add(($event | ConvertTo-Json -Compress -Depth 4))
            }
        }
    }
    $path = Join-Path $Out $file
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, (($lines -join "`n") + "`n"), $utf8)
    "{0,-22} {1,7} events" -f $file, $lines.Count
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$all = { $true }
$ps = 'Microsoft-Windows-PowerShell/Operational'
if ($Format -eq 'agent') {
    # Security alone needs the elevated shell; the other channels do not, so they are a run of
    # their own.
    if ($Security) {
        Export-Log @('Security') 'security.ndjson' $all
    } else {
        Export-Log @('System', 'Application', $ps) 'events.ndjson' $all
    }
} else {
    Export-Log @('System') 'system.ndjson' $all
    Export-Log @('Application') 'application.ndjson' $all
    Export-Log @($ps) 'ps-script.ndjson' { param($r) $r.Id -eq 4104 }
    Export-Log @($ps) 'ps-other.ndjson' { param($r) $r.Id -ne 4104 }
}
