#Requires -Version 5.1
<#
  Blackveil Endpoint Agent (Windows, Microsoft Defender Antivirus)

  Runs in the foreground of an elevated PowerShell window you open yourself. It
  never elevates itself, never disables protection, never executes suspicious
  files and never uploads file contents. It sends only threat names, Defender
  status codes, file paths and SHA-256 hashes. Stop it at any time with Ctrl+C.

  Usage (in PowerShell opened with "Run as administrator"):
    powershell -ExecutionPolicy Bypass -File .\blackveil-agent.ps1 -Server <agent URL from Blackveil>
  Add -ResetToken to replace a stored device token.
#>
param(
  [Parameter(Mandatory = $true)][string]$Server,
  [switch]$ResetToken
)

$ErrorActionPreference = 'Stop'
$AgentVersion = '1.0.0'
$PollSeconds = 15
$ConfigDir = Join-Path $env:ProgramData 'Blackveil'
$TokenFile = Join-Path $ConfigDir 'device-token.dat'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($Server -notmatch '^https://[A-Za-z0-9.-]+/functions/v1/endpoint-agent$') {
  Write-Host 'The -Server value must be the agent URL shown in Blackveil.' -ForegroundColor Red; exit 1
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'Microsoft Defender scans and remediation need administrator rights. Close this window, open PowerShell with "Run as administrator", and start the agent again.' -ForegroundColor Yellow; exit 1
}
if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
  Write-Host 'Microsoft Defender Antivirus PowerShell module was not found. This agent supports Windows 10, Windows 11 and Windows Server 2016 or newer with Defender installed.' -ForegroundColor Red; exit 1
}

function Get-Token {
  if ($ResetToken -and (Test-Path $TokenFile)) { Remove-Item $TokenFile -Force }
  if (-not (Test-Path $TokenFile)) {
    New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
    $sec = Read-Host -AsSecureString 'Paste the device token shown in Blackveil'
    $sec | ConvertFrom-SecureString | Set-Content -Path $TokenFile
    icacls $TokenFile /inheritance:r /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):(R,W)" 'SYSTEM:(F)' | Out-Null
  }
  $sec = Get-Content $TokenFile | ConvertTo-SecureString
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
  try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-EngineStatus {
  $s = Get-MpComputerStatus
  $updated = $null
  if ($s.AntivirusSignatureLastUpdated) { $updated = $s.AntivirusSignatureLastUpdated.ToString('o') }
  @{
    antivirusEnabled   = [bool]$s.AntivirusEnabled
    realTimeProtection = [bool]$s.RealTimeProtectionEnabled
    runningMode        = [string]$s.AMRunningMode
    signatureVersion   = [string]$s.AntivirusSignatureVersion
    signatureUpdated   = $updated
  }
}

function Invoke-Api([hashtable]$Body) {
  $Body.engineStatus = Get-EngineStatus
  $Body.osVersion = [string](Get-CimInstance Win32_OperatingSystem).Caption + ' ' + [Environment]::OSVersion.Version.ToString()
  $Body.agentVersion = $AgentVersion
  $json = $Body | ConvertTo-Json -Depth 8 -Compress
  for ($i = 0; $i -lt 3; $i++) {
    try {
      return Invoke-RestMethod -Uri $Server -Method Post -Headers @{ 'x-device-token' = $script:Token } -ContentType 'application/json' -Body $json -TimeoutSec 30
    } catch {
      $code = $null
      if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
      if ($code -eq 401) { throw 'TOKEN_REJECTED' }
      if ($code -ge 400 -and $code -lt 500) { throw "Server rejected the request ($code)" }
      Start-Sleep -Seconds ([math]::Pow(2, $i) * 2)
    }
  }
  throw 'Blackveil could not be reached after 3 attempts'
}

function Get-FilePaths($Resources) {
  @($Resources | Where-Object { $_ } | ForEach-Object {
    if ([string]$_ -match '^(?:file|containerfile):_(.+)$') { $Matches[1] }
  })
}

function Test-AllowedPath([string]$Path, $Allowed) {
  $t = $Path.Trim().Replace('/', '\').TrimEnd('\').ToLowerInvariant()
  foreach ($a in @($Allowed)) {
    $b = ([string]$a).Trim().Replace('/', '\').TrimEnd('\').ToLowerInvariant()
    if ($t -eq $b -or $t.StartsWith($b + '\')) { return $true }
  }
  $false
}

function Get-ThreatReport {
  $threats = @(Get-MpThreat -ErrorAction SilentlyContinue)
  $detections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
  $out = @()
  foreach ($t in $threats) {
    $det = $detections | Where-Object { $_.ThreatID -eq $t.ThreatID } | Sort-Object LastThreatStatusChangeTime -Descending | Select-Object -First 1
    $resources = @(@($t.Resources) + @($det.Resources) | Where-Object { $_ } | Select-Object -Unique -First 25)
    $sha = $null
    foreach ($p in (Get-FilePaths $resources)) {
      if (Test-Path -LiteralPath $p -PathType Leaf) {
        try { $sha = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash; break } catch { }
      }
    }
    $statusId = $null
    if ($det) { $statusId = [int]$det.ThreatStatusID }
    $out += @{
      threatId   = [string]$t.ThreatID
      name       = [string]$t.ThreatName
      severityId = [int]$t.SeverityID
      category   = ([string]$t.ThreatName -split ':')[0]
      resources  = $resources
      sha256     = $sha
      active     = [bool]$t.IsActive
      statusId   = $statusId
    }
  }
  , $out
}

function Invoke-Scan($Params, $AllowedPaths) {
  try { Update-MpSignature -ErrorAction Stop } catch { Write-Warning 'Signature update failed; scanning with current signatures.' }
  switch ([string]$Params.scanType) {
    'quick' { Start-MpScan -ScanType QuickScan }
    'full' { Start-MpScan -ScanType FullScan }
    'custom' {
      $p = [string]$Params.path
      if (-not (Test-AllowedPath $p $AllowedPaths)) { return @{ ok = $false; error = 'Requested folder is outside the authorized scope'; data = @{ code = 'scope_denied' } } }
      if (-not (Test-Path -LiteralPath $p)) { return @{ ok = $false; error = 'Folder not found on this device'; data = @{ code = 'path_not_found' } } }
      Start-MpScan -ScanType CustomScan -ScanPath $p
    }
    default { return @{ ok = $false; error = 'Unsupported scan type'; data = @{ code = 'bad_scan_type' } } }
  }
  @{ ok = $true; data = @{ engineStatus = Get-EngineStatus; threats = (Get-ThreatReport) } }
}

function Get-RebootState {
  try { $state = [int](Get-MpComputerStatus).ComputerState } catch { return @{ reboot = $false; offline = $false } }
  @{ reboot = [bool]($state -band 2); offline = [bool]($state -band 8) }
}

function Invoke-Remediate($Params) {
  $approved = @($Params.engineThreatIds | ForEach-Object { [string]$_ })
  $active = @(Get-MpThreat -ErrorAction SilentlyContinue | Where-Object { $_.IsActive } | ForEach-Object { [string]$_.ThreatID })
  $unapproved = @($active | Where-Object { $approved -notcontains $_ })
  if ($unapproved.Count -gt 0) {
    return @{ ok = $false; error = 'New active detections appeared that were not approved. Run a new scan and review them first.'; data = @{ code = 'unapproved_threats_present' } }
  }
  $removeError = $null
  try { Remove-MpThreat } catch { $removeError = $_.Exception.Message }
  Start-Sleep -Seconds 5
  $detections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
  $results = @(foreach ($id in $approved) {
    $d = $detections | Where-Object { [string]$_.ThreatID -eq $id } | Sort-Object LastThreatStatusChangeTime -Descending | Select-Object -First 1
    $statusId = $null
    if ($d) { $statusId = [int]$d.ThreatStatusID }
    $existing = @(Get-FilePaths $d.Resources | Where-Object { Test-Path -LiteralPath $_ })
    @{ threatId = $id; statusId = $statusId; existingResources = $existing }
  })
  $rb = Get-RebootState
  if ($rb.reboot) { Write-Host 'Defender reports a restart is required to finish removing a locked or running threat.' -ForegroundColor Yellow }
  @{ ok = $true; data = @{ results = $results; rebootRequired = $rb.reboot; offlineScanRequired = $rb.offline; engineError = $removeError } }
}

function Get-PersistenceEntries {
  $entries = @()
  $keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
          'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
          'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
  foreach ($k in $keys) {
    if (Test-Path $k) {
      $props = Get-ItemProperty -Path $k
      foreach ($p in $props.PSObject.Properties) { if ($p.Name -notlike 'PS*') { $entries += "registry:$k\$($p.Name) = $($p.Value)" } }
    }
  }
  try {
    foreach ($task in Get-ScheduledTask) {
      foreach ($a in $task.Actions) { if ($a.Execute) { $entries += "task:$($task.TaskPath)$($task.TaskName) = $($a.Execute) $($a.Arguments)" } }
    }
  } catch { }
  $startup = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")
  foreach ($s in $startup) { if (Test-Path $s) { Get-ChildItem -LiteralPath $s -File | ForEach-Object { $entries += "startup:$($_.FullName)" } } }
  $entries
}

function Invoke-Verify($Params) {
  try { Update-MpSignature -ErrorAction Stop } catch { }
  Start-MpScan -ScanType QuickScan
  $dirs = @($Params.resources | ForEach-Object { Get-FilePaths $_.resources } | ForEach-Object { Split-Path -Parent $_ } |
    Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique -First 5)
  foreach ($dir in $dirs) { Start-MpScan -ScanType CustomScan -ScanPath $dir }
  $active = @(Get-MpThreat -ErrorAction SilentlyContinue | Where-Object { $_.IsActive } | ForEach-Object { [string]$_.ThreatID })
  $persistence = @(Get-PersistenceEntries)
  $items = @(foreach ($entry in @($Params.resources)) {
    $id = [string]$entry.threatId
    $files = @(Get-FilePaths $entry.resources)
    $existing = @($files | Where-Object { Test-Path -LiteralPath $_ })
    $hits = @($persistence | Where-Object { $line = $_.ToLowerInvariant(); @($files | Where-Object { $line.Contains($_.ToLowerInvariant()) }).Count -gt 0 } | Select-Object -First 25)
    @{ threatId = $id; activeDetection = ($active -contains $id); existingResources = $existing; persistenceHits = $hits }
  })
  @{ ok = $true; data = @{ engineStatus = Get-EngineStatus; items = $items } }
}

function Invoke-Restore($Params) {
  $name = [string]$Params.name
  if ($name -notmatch '^[A-Za-z0-9:/._!#\-]+$') { return @{ ok = $false; error = 'Unexpected threat name format'; data = @{ code = 'bad_name' } } }
  $mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
  & $mp -Restore -Name $name | Out-Null
  $exit = $LASTEXITCODE
  $files = @(Get-FilePaths $Params.resources)
  $exists = @($files | Where-Object { Test-Path -LiteralPath $_ }).Count -gt 0
  if ($exit -ne 0) { return @{ ok = $false; error = "Defender restore exited with code $exit"; data = @{ code = 'restore_failed' } } }
  @{ ok = $true; data = @{ restored = $true; fileExists = $exists } }
}

function Invoke-Job($Job, $AllowedPaths) {
  Write-Host "[$(Get-Date -Format T)] Running $($Job.kind) job..." -ForegroundColor Cyan
  try {
    switch ([string]$Job.kind) {
      'scan' { $r = Invoke-Scan $Job.params $AllowedPaths }
      'remediate' { $r = Invoke-Remediate $Job.params }
      'verify' { $r = Invoke-Verify $Job.params }
      'restore' { $r = Invoke-Restore $Job.params }
      default { $r = @{ ok = $false; error = 'Unsupported job'; data = @{} } }
    }
  } catch {
    $msg = [string]$_.Exception.Message
    if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }
    $r = @{ ok = $false; error = $msg; data = @{ code = 'agent_exception' } }
  }
  Invoke-Api @{ action = 'report'; jobId = [string]$Job.id; ok = [bool]$r.ok; error = $r.error; data = $r.data } | Out-Null
  Write-Host "[$(Get-Date -Format T)] $($Job.kind) finished (ok=$($r.ok))." -ForegroundColor Gray
}

$script:Token = Get-Token
Write-Host "Blackveil agent $AgentVersion connected. Waiting for actions you approve in Blackveil. Press Ctrl+C to stop." -ForegroundColor Green
while ($true) {
  try {
    $resp = Invoke-Api @{ action = 'poll' }
    if ($resp.job) { Invoke-Job $resp.job $resp.allowedPaths }
  } catch {
    if ([string]$_.Exception.Message -eq 'TOKEN_REJECTED') {
      Write-Host 'This device token was revoked or is invalid. Enroll the device again in Blackveil and run the agent with -ResetToken.' -ForegroundColor Red; exit 1
    }
    Write-Warning $_.Exception.Message
  }
  Start-Sleep -Seconds $PollSeconds
}
