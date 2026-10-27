# Installation

Supported: macOS, Linux, Windows via WSL2 / PowerShell.

## Profiles

| Profile | Command | Includes |
|---|---|---|
| Base orchestrator | `bash installers/install.sh base` | core CLI, scope, reporting |
| MCP | `bash installers/install.sh mcp` | base + MCP SDK server |
| Dev | `bash installers/install.sh dev` | MCP + pytest |

Optional Briar engine (isolated):

```bash
python3 -m venv .venv-briar
.venv-briar/bin/pip install 'briar-pentest==0.4.62'
export PEN_BRIAR_PYTHON=$PWD/.venv-briar/bin/python
```

Shannon still requires Docker + Node.js 18+ separately.

## Optional local static scanners

These optional adapters are not installed by the default MCP profile. They scan only configured local source/configuration paths; they do not enable remote network scanning.

Checkov 3.3.29 is pinned for Python 3.10–3.12 in this project. MobSFScan 1.0.1 checks mobile source-code patterns; it is not the MobSF APK/IPA binary analyzer and does not perform emulator/device runtime testing.

~~~bash
# Activate this repository's virtual environment first.
python -m pip install -e ".[checkov,mobsfscan]"
python -m core.cli health --tool checkov
python -m core.cli health --tool mobsfscan
python -m core.cli capabilities --tool checkov
python -m core.cli capabilities --tool mobsfscan
~~~

For the initial run, use dry-run mode and a source/configuration directory under an allowed workspace root. A healthy dependency check does not grant permission to scan a path. The adapters refuse paths outside the configured work/report roots or current workspace.

License references: [Checkov](https://github.com/bridgecrewio/checkov) (Apache-2.0), [MobSFScan](https://github.com/MobSF/mobsfscan) (LGPL-3.0-or-later). Review transitive dependencies and the intended distribution model before redistributing these optional engines.

## One-command setup

```bash
git clone https://github.com/eneelkant/pen-testing.git
cd pen-testing
chmod +x installers/*.sh scripts/*.sh
# Non-interactive CI-style:
PEN_ASSUME_YES=1 bash scripts/setup_all.sh
```

## Manual MCP verification

```bash
source .venv/bin/activate
pen-testing-mcp   # stdio server for Cursor/Claude
python -c "from mcp_server.server import mcp; print([t.name for t in mcp.list_tools()])"
python -m core.cli doctor
```

## Client configuration

See `docs/CLIENT_COMPATIBILITY.md`.

```bash
python installers/configure_cursor.py --apply
python installers/configure_claude.py --print-only
python installers/configure_gemini.py --print-only
```

Installers create backups before modifying existing MCP configs and only upsert the `pen-testing` server entry.

## Docker

Not installed by these scripts. Official docs: https://docs.docker.com/get-docker/

```bash
docker compose version
bash scripts/docker_runtime_verify.sh
# Equivalent steps: compose config -q, build orchestrator + briar, run orchestrator doctor, host smoke
```

## Uninstall

```bash
deactivate || true
rm -rf .venv .venv-briar
# Remove MCP entries manually from client configs if applied
docker compose down -v  # if used
```
