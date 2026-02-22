# AIWRE Release Process

Use this process for every public release.

## 1) Prepare notes
- Update `inbox/release-vX.Y.Z.md` (release notes).
- Update `inbox/update-notice-vX.Y.Z.md` (short X-ready notice).
- Copy to `inbox/update-notice.latest.md`.

## 2) Ship code
- Ensure `main` is green: `go test -vet=off ./...`.
- Push `main` first.

## 3) Create GitHub release
- `gh release create vX.Y.Z --target main --title vX.Y.Z --notes-file inbox/release-vX.Y.Z.md --latest`

## 4) Verify website KPI version
- KPI panel should show `RELEASE_VERSION = vX.Y.Z` (from latest GitHub release).
- Check: `curl -sS https://aiwre.io/api/kpi | jq '.release_tag,.kpi.running_version'`

## 5) Publish update notice
- Read `inbox/update-notice.latest.md` and publish to X.

## 6) Consistency gate (required)
- Run:
  - `bash scripts/check_release_consistency.sh`
- This verifies all three match:
  - GitHub latest release tag
  - aiwre.io KPI `RELEASE_VERSION`
  - `update-notice.latest.md` version string
