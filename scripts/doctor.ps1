$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$env:PYTHONPATH = if ($env:PYTHONPATH) { "$Root;$env:PYTHONPATH" } else { $Root }
python -m core.cli doctor @args
