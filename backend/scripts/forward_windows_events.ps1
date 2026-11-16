<#
.SYNOPSIS
  Forwards recent Windows Security / Sysmon events to SENTRIX AI.

.DESCRIPTION
  Reads events with Get-WinEvent (run as Administrator to read the Security log),
  converts each event's XML EventData into a JSON object and POSTs batches to
  /api/events/batch with format "windows" or "sysmon". Read-only on the host.

.EXAMPLE
  .\forward_windows_events.ps1 -Minutes 60
  .\forward_windows_events.ps1 -LogName "Microsoft-Windows-Sysmon/Operational" -Format sysmon
#>
param(
  [string]$Api = $(if ($env:SENTRIX_API) { $env:SENTRIX_API } else { "http://127.0.0.1:8000" }),
  [string]$LogName = "Security",
  [ValidateSet("windows", "sysmon")][string]$Format = "windows",
  [int]$Minutes = 60,
  [int]$MaxEvents = 2000,
  [int[]]$EventIds = @(1102, 4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4728, 4732, 4740, 4756, 4769, 5140)
)

$filter = @{ LogName = $LogName; StartTime = (Get-Date).AddMinutes(-$Minutes) }
if ($Format -eq "windows" -and $EventIds) { $filter.Id = $EventIds }

$events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
if (-not $events) { Write-Host "No events found."; exit 0 }

$payloads = foreach ($e in $events) {
  $xml = [xml]$e.ToXml()
  $data = @{}
  foreach ($d in $xml.Event.EventData.Data) { if ($d.Name) { $data[$d.Name] = $d.'#text' } }
  @{
    format = $Format
    source = $LogName
    raw    = @{
      EventID     = $e.Id
      TimeCreated = $e.TimeCreated.ToUniversalTime().ToString("o")
      Computer    = $e.MachineName
      EventData   = $data
    }
  }
}

$headers = @{ "X-Actor" = "windows-forwarder-$env:COMPUTERNAME" }
if ($env:SENTRIX_API_KEY) { $headers["X-API-Key"] = $env:SENTRIX_API_KEY }

for ($i = 0; $i -lt $payloads.Count; $i += 500) {
  $chunk = @($payloads[$i..([Math]::Min($i + 499, $payloads.Count - 1))])
  $body = @{ events = $chunk; analyze = $true } | ConvertTo-Json -Depth 6
  $resp = Invoke-RestMethod -Method Post -Uri "$Api/api/events/batch" -Headers $headers `
          -ContentType "application/json" -Body $body
  Write-Host ("accepted={0} duplicates={1} rejected={2} incidents={3}" -f `
    $resp.accepted, $resp.duplicates, $resp.rejected, ($resp.incidents_touched -join ","))
}
