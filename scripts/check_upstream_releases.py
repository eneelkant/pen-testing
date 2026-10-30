#!/usr/bin/env python3
"""Check upstream repos for new stable releases since last evaluation.

Monitors: KeygraphHQ/shannon, temporalio/temporal, zricethezav/gitleaks, aquasecurity/trivy.
Compares latest stable release against the last-evaluated version recorded in
scripts/upstream_release_state.json. Prints a report; never changes production pins.

Usage: python scripts/check_upstream_releases.py [--update-state]

Exit codes:
  0: No new releases detected (or --update-state used)
  1: New release(s) detected — review needed
  2: Error contacting upstream API
"""
import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

STATE_FILE = Path(__file__).parent / "upstream_release_state.json"

UPSTREAM_REPOS = {
    "shannon": {
        "github_repo": "KeygraphHQ/shannon",
        "docker_repo": "keygraph/shannon",
        "last_evaluated_tag": "v3.5.0",
        "production_pin_tag": "3.4.0",
    },
    "temporal": {
        "github_repo": "temporalio/temporal",
        "docker_repo": "temporalio/temporal",
        "last_evaluated_tag": "v1.32.1",
        "production_pin_tag": "1.7.0",
    },
    "gitleaks": {
        "github_repo": "zricethezav/gitleaks",
        "docker_repo": "zricethezav/gitleaks",
        "last_evaluated_tag": "v8.30.1",
        "production_pin_tag": "v8.21.2",
    },
    "trivy": {
        "github_repo": "aquasecurity/trivy",
        "docker_repo": "aquasec/trivy",
        "last_evaluated_tag": "v0.76.1",
        "production_pin_tag": "0.76.0",
    },
}


def fetch_latest_release(github_repo: str) -> dict | None:
    """Fetch the latest non-prerelease from GitHub API."""
    url = f"https://api.github.com/repos/{github_repo}/releases?per_page=10"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "pen-testing-release-monitor",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            releases = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        print(f"ERROR: cannot fetch releases for {github_repo}: {exc}", file=sys.stderr)
        return None
    for r in releases:
        if not r.get("prerelease") and not r.get("draft"):
            return r
    return None


def fetch_docker_tag(docker_repo: str, tag: str) -> str | None:
    """Fetch the linux/amd64 digest for a Docker Hub tag."""
    url = f"https://hub.docker.com/v2/repositories/{docker_repo}/tags/{tag}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "pen-testing-release-monitor"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for img in data.get("images", []):
            if img.get("architecture") == "amd64" and img.get("os") == "linux":
                return img.get("digest", "")
    except Exception:
        pass
    return None


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check upstream repos for new stable releases.")
    parser.add_argument("--update-state", action="store_true", help="Update the state file with latest releases")
    parser.add_argument("--token", default="", help="GitHub token for authenticated API access")
    args = parser.parse_args()

    state = load_state()
    new_releases = []
    now = datetime.now(timezone.utc).isoformat()

    print("=" * 64)
    print("Upstream Release Monitor Report")
    print(f"Generated: {now}")
    print("=" * 64)

    for name, config in UPSTREAM_REPOS.items():
        github_repo = config["github_repo"]
        last_eval = config["last_evaluated_tag"]
        prod_pin = config["production_pin_tag"]

        print(f"\n--- {name} ({github_repo}) ---")
        print(f"  production pin: {prod_pin}")
        print(f"  last evaluated: {last_eval}")

        release = fetch_latest_release(github_repo)
        if release is None:
            print(f"  latest release: UNAVAILABLE (API error or no stable releases)")
            continue

        latest_tag = release.get("tag_name", "?")
        published = release.get("published_at", "?")[:10]
        is_new = latest_tag != last_eval

        print(f"  latest release: {latest_tag} (published {published})")
        print(f"  new release detected: {is_new}")

        if is_new:
            # Resolve Docker Hub digest
            docker_tag = latest_tag.lstrip("v") if name != "gitleaks" else latest_tag
            digest = fetch_docker_tag(config["docker_repo"], docker_tag)
            print(f"  docker digest: {digest or 'UNAVAILABLE'}")
            print(f"  release URL: {release.get('html_url', '?')}")
            body = (release.get("body") or "")[:200]
            print(f"  release notes: {body}")

            new_releases.append({
                "name": name,
                "github_repo": github_repo,
                "tag": latest_tag,
                "published": published,
                "docker_digest": digest,
                "release_url": release.get("html_url"),
                "production_pin": prod_pin,
            })

        if args.update_state:
            state[name] = {
                "last_evaluated_tag": latest_tag,
                "last_checked": now,
            }

    if args.update_state:
        save_state(state)
        print(f"\nState file updated: {STATE_FILE}")

    print(f"\n{'=' * 64}")
    print(f"Summary: {len(new_releases)} new release(s) detected")
    if new_releases:
        print("NEW RELEASES REQUIRE EVALUATION:")
        for r in new_releases:
            print(f"  {r['name']}: {r['tag']} (published {r['published']})")
            print(f"    → Run the candidate pipeline to evaluate this release")
            print(f"    → Do NOT change production pins without full acceptance evidence")
        return 1
    else:
        print("No new releases detected. All upstream projects at previously evaluated versions.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
