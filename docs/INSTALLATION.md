# Installation

Supported: macOS, Linux, Windows via WSL2 (PowerShell scripts included).

## Prerequisites

| Prerequisite | Why |
|---|---|
| Git | Clone repository |
| Python 3.10+ | Orchestrator |
| Docker Engine/Desktop + Compose v2 | Shannon workers; recommended isolation |
| Node.js 18+ | Shannon `npx` launcher |
| AI provider credentials | Only when running Shannon/Briar agents that need them |

This project does **not** silently install Docker. Official docs: https://docs.docker.com/get-docker/

## Quick start

```bash
git clone https://github.com/eneelkant/pen-testing.git
cd pen-testing
chmod +x scripts/*.sh
./scripts/setup.sh
./scripts/doctor.sh
make smoke
```

Windows (PowerShell):

```powershell
git clone https://github.com/eneelkant/pen-testing.git
cd pen-testing
./scripts/setup.ps1
./scripts/doctor.ps1
```

## Docker-first

```bash
cp .env.example .env   # add keys only if needed
docker compose build
docker compose run --rm orchestrator
# Briar worker image
docker compose --profile workers build briar
# Local headers fixture
docker compose --profile fixtures up -d fixture-headers
```

Uninstall/cleanup:

```bash
docker compose --profile workers --profile fixtures down -v
docker image rm pen-testing-orchestrator:0.1.0 pen-testing-briar:0.4.62 || true
```

## Isolated Briar venv

```bash
python3 -m venv .venv-briar
.venv-briar/bin/pip install 'briar-pentest==0.4.62'
export PEN_BRIAR_PYTHON=$PWD/.venv-briar/bin/python
python -m core.cli health --tool briar
```

## Troubleshooting

| Symptom | Check |
|---|---|
| `docker: NOT FOUND` | Install Docker; re-run doctor |
| Docker installed but daemon errors | Start Docker Desktop / enable service |
| Shannon health `cli_reachable` false | Node/npx network access to npm registry |
| Briar `installed` false | Set `PEN_BRIAR_PYTHON` to the venv that has `briar-pentest` |
| Scope check denies target | Add explicit authorization record; do not disable checks |
| `python3 -m venv` fails | Install `python3-venv` (Debian/Ubuntu) |

## Verified in agent environment (2026-10-12)

| Check | Result |
|---|---|
| Python 3.12.3 | Passed |
| Node/npx | Passed; Shannon CLI help for 3.4.0 retrieved |
| Briar 0.4.62 CLI via pip `--target` | Passed |
| Docker Engine | **Missing** — compose builds not executed here |
