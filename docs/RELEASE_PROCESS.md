# Release Process

Semantic versioning. Current distributable line: **0.2.0a18** (alpha — not production-ready). `0.2.0a17` records the upstream image gate. `0.2.0a16` is the strict-deployment and image-gate follow-up. Merged `0.2.0a15` is the operator, encryption, and image-pin follow-up. Merged `0.2.0a14` is operational reliability and supply-chain metadata. Merged `0.2.0a13` is the destination-policy and Shannon full-pipeline gate. Those releases remain in the changelog.

## Compatibility policy

- Direct dependencies declared in `pyproject.toml` with compatible ranges.
- Reproducible pins live under `requirements/*.txt` and are refreshed per release after review.
- Optional extras: `mcp`, `briar`, `dev`.

## Preconditions

1. CI green on the release commit
2. Unit/smoke tests passed
3. Licensing/attribution reviewed (`THIRD_PARTY_NOTICES.md`)
4. No secrets in the tree
5. Docker build/run verified on a machine with Docker before calling a release "fully validated"
6. Explicit maintainer authorization to publish tags/packages

## Steps

```bash
# 1. Update CHANGELOG.md and version in pyproject.toml / mcp_server/__init__.py
# 2. Push to main via reviewed PR
# 3. Tag
git tag -a v0.2.0a1 -m "v0.2.0a1"
git push origin v0.2.0a1
```

GitHub Actions `release.yml` creates a GitHub Release for tags matching `v*`.

## Publishing targets

| Target | Status |
|---|---|
| GitHub source release | Supported via tag + workflow |
| PyPI | **Not configured** — do not publish without ownership/credentials |
| Container registry | **Not configured** — compose images are local build only |

## Rollback

Delete the GitHub release and tag if published in error; revert the version bump commit on `main`.
