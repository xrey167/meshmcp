# meshmcp live mesh demo — launches one gateway (4 different MCP servers) and
# four agent apps (each its own mesh identity), and opens the Control Room.
# Requires: Go, and $env:NB_SETUP_KEY set to a REUSABLE NetBird setup key.
#   $env:NB_SETUP_KEY = "<your-reusable-setup-key>"
#   ./demo/run-mesh.ps1
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)   # repo root

if (-not $env:NB_SETUP_KEY) {
  Write-Error "Set a reusable NetBird setup key first:  `$env:NB_SETUP_KEY = '<key>'  (app.netbird.io -> Setup Keys)"
  exit 1
}

Write-Host "==> building binaries" -ForegroundColor Cyan
go build -o meshmcp.exe .
go build -o cmd/mcpserver/mcpserver.exe ./cmd/mcpserver/prompt_mcp

New-Item -ItemType Directory -Force -Path demo | Out-Null
if (-not (Test-Path demo/secrets.json)) {
  Set-Content -NoNewline -Path demo/secrets.json -Value '{"stripe_key":"sk_live_demo_PLACEHOLDER"}'
}
Remove-Item demo/audit.jsonl,demo/trace.jsonl -ErrorAction SilentlyContinue

$script:procs = @()
function Start-Bg([string]$name, [string[]]$argv) {
  $p = Start-Process -FilePath ".\meshmcp.exe" -ArgumentList $argv -PassThru -NoNewWindow `
        -RedirectStandardError "demo/$name.log" -RedirectStandardOutput "demo/$name.out"
  $script:procs += $p
  return $p
}

Write-Host "==> starting gateway (fs · web · payments · customer-db)" -ForegroundColor Cyan
Start-Bg "gateway" @("serve","--config","examples/demo-mesh.yaml") | Out-Null

# Wait for the gateway to report its mesh IP.
$ip = $null
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 750
  if (Test-Path demo/gateway.log) {
    $m = Select-String -Path demo/gateway.log -Pattern 'mesh peer up:\s*([\d.]+)' | Select-Object -First 1
    if ($m) { $ip = $m.Matches[0].Groups[1].Value; break }
  }
}
if (-not $ip) { Write-Error "gateway didn't report a mesh IP — see demo/gateway.log"; foreach ($p in $procs) { $p.Kill() }; exit 1 }
Write-Host "==> gateway mesh IP: $ip" -ForegroundColor Green

Write-Host "==> Control Room -> http://127.0.0.1:9900" -ForegroundColor Cyan
Start-Bg "room" @("room","--audit","demo/audit.jsonl","--addr","127.0.0.1:9900","--title","meshmcp live mesh demo") | Out-Null
Start-Sleep -Seconds 1
Start-Process "http://127.0.0.1:9900"

Write-Host "==> starting agent apps (each its own mesh identity)" -ForegroundColor Cyan
Start-Bg "agent-reader"  @("agent","--role","reader", "--device-name","agent-reader", "--nb-config","demo/agent-reader-nb.json", "--interval","3s","$($ip):9101") | Out-Null
Start-Bg "agent-fetcher" @("agent","--role","fetcher","--device-name","agent-fetcher","--nb-config","demo/agent-fetcher-nb.json","--interval","4s","$($ip):9102") | Out-Null
Start-Bg "agent-billing" @("agent","--role","billing","--device-name","agent-billing","--nb-config","demo/agent-billing-nb.json","--interval","5s","$($ip):9103") | Out-Null
Start-Bg "agent-analyst" @("agent","--role","analyst","--device-name","agent-analyst","--nb-config","demo/agent-analyst-nb.json","--interval","4s","$($ip):9104") | Out-Null

Write-Host ""
Write-Host "LIVE — watch the Control Room. Ctrl+C stops everything." -ForegroundColor Green
try {
  while ($true) { Start-Sleep -Seconds 2 }
} finally {
  Write-Host "`n==> stopping" -ForegroundColor Cyan
  foreach ($p in $script:procs) { try { $p.Kill() } catch {} }
}
