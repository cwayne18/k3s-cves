# k3s-cves

Automated [Trivy](https://github.com/aquasecurity/trivy) CVE scanning for
[k3s](https://github.com/k3s-io/k3s), published as a dashboard on GitHub Pages.

This is a k3s-focused port of the RKE2 CVE dashboard. It scans the container
images shipped with k3s **plus the k3s binary itself**, tracks CRITICAL/HIGH
findings over time, and renders styled HTML reports themed after
[k3s.io](https://k3s.io).

## How it works

`scan.sh` assembles what to scan, then runs Trivy over each target:

| Mode | Image list | Binary |
| --- | --- | --- |
| **branch** (default `main`) | `scripts/airgap/image-list.txt` from the branch | latest `k3s-amd64` CI artifact from the most recent run on that branch |
| **release** (`--release vX.Y.Z+k3sN`) | `k3s-images.txt` from the GitHub release | `k3s` binary asset from the release |
| **pr** (`--pr <num>`) | image list from the PR head | `k3s` binary from the most recent CI run for the PR |

Findings (aggregate counts and per-CVE identities) are persisted to a small
SQLite database (`reports/scan_metrics.db`) so the dashboard can plot CVE trends
per source. Where it applies, the upstream
[Rancher VEX hub](https://github.com/rancher/vexhub) OpenVEX report is used to
suppress known non-applicable findings on the `rancher/mirrored-*` images k3s
bundles.

## Usage

```bash
# Scan the default (main) branch: airgap image list + latest k3s binary build
./scan.sh

# Scan a release branch
./scan.sh release-1.33

# Scan a published release (images list + binary)
./scan.sh --release v1.36.1+k3s1

# Scan a pull request's images + binary
./scan.sh --pr 9994

# Upload the report to a public gist
./scan.sh --gist 'My k3s scan'
```

Requirements: `trivy`, `gh` (authenticated), `curl`, and optionally `python3`
and `sqlite3` (for CVE source attribution and the metrics database).

## Dashboard

The GitHub Actions workflows scan on a daily schedule, convert each Markdown
report to HTML with `.github/scripts/scan_to_html.py`, and deploy
`reports/html/` to GitHub Pages. The generated `index.html` lists every report
and leads with an interactive CVE trend chart.

- `.github/workflows/scan-report.yml` — runs `scan.sh`, renders HTML, commits the report.
- `.github/workflows/deploy-pages.yml` — publishes `reports/html/` to GitHub Pages.

## Credits

Ported from [cwayne18/rke2-toolbox](https://github.com/cwayne18/rke2-toolbox).
The Trivy SBOM patch and VEX-suppression approach follow
[rancher/image-scanning](https://github.com/rancher/image-scanning).
