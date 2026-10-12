$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "== pen-testing setup =="
Write-Host "Repository: $Root"
Write-Host "This script will not silently install Docker or change host packages."

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  Write-Error "python is required on PATH"
}

if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
  $ans = Read-Host "Create .env from .env.example? [y/N]"
  if ($ans -match '^[yY]$') { Copy-Item ".env.example" ".env" }
}

if (-not (Test-Path ".venv")) {
  $ans = Read-Host "Create orchestrator venv .venv and install project? [y/N]"
  if ($ans -match '^[yY]$') {
    python -m venv .venv
    & .\.venv\Scripts\python -m pip install -U pip
    & .\.venv\Scripts\pip install -e ".[dev]"
  }
}

if (-not (Test-Path ".venv-briar")) {
  $ans = Read-Host "Create isolated Briar venv .venv-briar? [y/N]"
  if ($ans -match '^[yY]$') {
    python -m venv .venv-briar
    & .\.venv-briar\Scripts\pip install -U pip
    & .\.venv-briar\Scripts\pip install "briar-pentest==0.4.62"
  }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Host "Docker is NOT installed. See https://docs.docker.com/get-docker/"
}

$env:PYTHONPATH = if ($env:PYTHONPATH) { "$Root;$env:PYTHONPATH" } else { $Root }
python -m core.cli doctor
Write-Host "Setup finished. Run: make smoke"
