#!/usr/bin/env bash
set -euo pipefail

repo_api="${1:-https://api.github.com/repos/horacex/aiwre/releases/latest}"
kpi_api="${2:-https://aiwre.io/api/kpi}"
notice_raw="${3:-https://raw.githubusercontent.com/horacex/aiwre/main/inbox/update-notice.latest.md}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

need curl
need jq
need grep
need sed

gh_tag="$(curl -fsSL "$repo_api" | jq -r '.tag_name // empty')"
if [[ -z "$gh_tag" ]]; then
  echo "failed: unable to read github latest tag" >&2
  exit 1
fi

kpi_tag="$(curl -fsSL "$kpi_api" | jq -r '.release_tag // .kpi.running_version // empty')"
if [[ -z "$kpi_tag" ]]; then
  echo "failed: unable to read kpi release tag" >&2
  exit 1
fi

notice_text="$(curl -fsSL "$notice_raw")"
notice_tag="$(printf '%s\n' "$notice_text" | grep -Eo 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
if [[ -z "$notice_tag" ]]; then
  echo "failed: unable to parse version from update notice" >&2
  exit 1
fi

echo "github_latest_tag=$gh_tag"
echo "kpi_release_tag=$kpi_tag"
echo "notice_tag=$notice_tag"

if [[ "$gh_tag" != "$kpi_tag" || "$gh_tag" != "$notice_tag" ]]; then
  echo "mismatch: release versions are not unified" >&2
  exit 1
fi

echo "ok: release versions are unified"
