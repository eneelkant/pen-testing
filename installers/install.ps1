$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$ProfileName = if ($args.Count -ge 1) { $args[0] } else { "base" }

Write-Host "== pen-testing install ($ProfileName) =="
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  Write-Error "python is required (3.10+)"
}

if (-not (Test-Path ".venv")) {
  $ans = Read-Host "Create isolated venv .venv? [y/N]"
  if ($ans -notmatch '^[yY]$') { throw "Aborted" }
  python -m venv .venv
}

& .\.venv\Scripts\python -m pip install -U pip
switch ($ProfileName) {
  "base" { & .\.venv\Scripts\pip install -e . -c requirements/base.txt }
  "mcp"  { & .\.venv\Scripts\pip install -e ".[mcp]" -r requirements/mcp.txt }
  "dev"  { & .\.venv\Scripts\pip install -e ".[dev]" -r requirements/dev.txt }
  default { throw "Unknown profile: $ProfileName" }
}

if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
  $ans = Read-Host "Create .env from .env.example? [y/N]"
  if ($ans -match '^[yY]$') { Copy-Item ".env.example" ".env" }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Host "Docker is NOT installed. See https://docs.docker.com/get-docker/"
}

$env:PYTHONPATH = if ($env:PYTHONPATH) { "$Root;$env:PYTHONPATH" } else { $Root }
& .\.venv\Scripts\python -m core.cli doctor
Write-Host "Install complete. Run: .\.venv\Scripts\pen-testing-mcp"
