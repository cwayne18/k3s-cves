#!/bin/bash

# Trivy CVE scanner for K3s.
#
# Unlike RKE2 (which builds its image list from an upstream build-images script),
# K3s ships a flat airgap image list plus a single self-contained binary, so the
# image set is much simpler to assemble:
#
#   * branch mode (default): pull scripts/airgap/image-list.txt from the given
#     branch of k3s-io/k3s, and additionally pull + scan the freshly built k3s
#     binary from the most recent CI run on that branch.
#   * release mode (--release): pull the published k3s-images.txt and the k3s
#     binary directly from the GitHub release artifacts.
#   * pr mode (--pr): pull the image list from the PR head and the k3s binary
#     from the most recent CI run for that PR.

# Output file to store the Trivy scan reports
output_file="trivy_scan_report.txt"
db_file="${SCAN_STATS_DB_PATH:-reports/scan_metrics.db}"
branch=""
pr_input=""
gist_title=""
release_version=""

k3s_repo="k3s-io/k3s"

usage() {
    echo "Usage: $0 [branch] [--pr <pr-number|pr-url>] [--release <version>] [--gist <title>]"
    echo ""
    echo "Examples:"
    echo "  $0"
    echo "  $0 release-1.33"
    echo "  $0 --pr 9994"
    echo "  $0 --pr https://github.com/k3s-io/k3s/pull/9994"
    echo "  $0 --release v1.36.1+k3s1"
    echo "  $0 --gist 'My Scan Results'"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--pr)
            if [[ -z "$2" ]]; then
                echo "Error: --pr requires a value"
                usage
                exit 1
            fi
            pr_input="$2"
            shift 2
            ;;
        -g|--gist)
            if [[ -z "$2" ]]; then
                echo "Error: --gist requires a title value"
                usage
                exit 1
            fi
            gist_title="$2"
            shift 2
            ;;
        -r|--release)
            if [[ -z "$2" ]]; then
                echo "Error: --release requires a version value"
                usage
                exit 1
            fi
            release_version="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            # Backward-compatible positional branch argument.
            if [[ -z "$branch" ]]; then
                branch="$1"
                shift
            else
                echo "Error: Unknown argument '$1'"
                usage
                exit 1
            fi
            ;;
    esac
done

if [[ -z "$branch" ]]; then
    branch="main"
fi

# Validate mutually exclusive flags
if [[ -n "$release_version" && -n "$pr_input" ]]; then
    echo "Error: --release and --pr cannot be used together"
    usage
    exit 1
fi

if [[ -n "$release_version" ]]; then
    # K3s release tags use the form "vX.Y.Z+k3sN". Accept "-k3sN" as a friendly
    # alias and normalize to "+k3sN" so the tag matches the GitHub release name.
    release_tag="$release_version"
    if [[ "$release_tag" =~ ^(.*)-k3s([0-9]+)$ ]]; then
        release_tag="${BASH_REMATCH[1]}+k3s${BASH_REMATCH[2]}"
    fi
    release_tag_url="${release_tag//+/%2B}"
    source_desc="release ${release_tag}"
elif [[ -n "$pr_input" ]]; then
    if [[ "$pr_input" =~ ^[0-9]+$ ]]; then
        pr_number="$pr_input"
    elif [[ "$pr_input" =~ github\.com/k3s-io/k3s/pull/([0-9]+) ]]; then
        pr_number="${BASH_REMATCH[1]}"
    else
        echo "Error: --pr value must be a PR number or k3s-io/k3s PR URL"
        usage
        exit 1
    fi

    ref_path="refs/pull/${pr_number}/head"
    source_desc="PR #${pr_number}"

    # Fetch PR head SHA and head branch for artifact lookup
    pr_info_output=$(gh pr view "$pr_number" -R "$k3s_repo" --json headRefOid,headRefName,headRepositoryOwner 2>&1)
    pr_info_exit=$?
    if [[ $pr_info_exit -ne 0 ]]; then
        echo "Error fetching PR info: $pr_info_output"
        pr_head_sha=""
        pr_head_ref=""
    else
        pr_head_sha=$(echo "$pr_info_output" | grep -oE '"headRefOid":\s*"[^"]+"' | sed 's/.*"\([^"]*\)"$/\1/')
        pr_head_ref=$(echo "$pr_info_output" | grep -oE '"headRefName":\s*"[^"]+"' | sed 's/.*"\([^"]*\)"$/\1/')
        echo "PR head SHA: $pr_head_sha"
        echo "PR head ref: $pr_head_ref"
    fi
else
    ref_path="refs/heads/${branch}"
    source_desc="branch '${branch}'"
fi

# Canonical source reference recorded with the scan. Used both for the metrics
# DB row and for the metadata comment embedded in the report so HTML rendering
# can group the CVE trend chart by scan type (branch / release / PR).
source_ref="${ref_path:-release:${release_tag}}"

# Clear files if they already exist
rm -f "$output_file"
rm -f images.txt

echo "Scanning using ${source_desc} (${ref_path:-release tag $release_tag})"

# Always set up a work_dir + cleanup so the trap is consistent
work_dir=$(mktemp -d)
cleanup() {
    rm -rf "$work_dir"
    rm -f vex.openvex.json
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Assemble the image list
# ---------------------------------------------------------------------------
if [[ -n "$release_version" ]]; then
    # Release mode: download the published images list directly from the release.
    release_images_url="https://github.com/${k3s_repo}/releases/download/${release_tag_url}/k3s-images.txt"
    echo "Downloading release images list from: $release_images_url"
    if ! curl -fsSL "$release_images_url" -o images.txt; then
        echo "Error: Failed to download release images list from $release_images_url"
        echo "       Verify that the release tag '${release_tag}' exists at https://github.com/${k3s_repo}/releases"
        exit 1
    fi
else
    # Branch / PR mode: pull the airgap image list straight from the source tree.
    if [[ -n "$pr_input" ]]; then
        image_list_ref="${pr_head_sha:-refs/pull/${pr_number}/head}"
    else
        image_list_ref="$branch"
    fi
    image_list_url="https://raw.githubusercontent.com/${k3s_repo}/${image_list_ref}/scripts/airgap/image-list.txt"
    echo "Downloading airgap image list from: $image_list_url"
    if ! curl -fsSL "$image_list_url" -o images.txt; then
        echo "Error: Failed to download airgap image list from $image_list_url"
        exit 1
    fi
fi

# Normalize: drop blank lines / comments and de-duplicate while preserving order.
awk 'NF && $0 !~ /^[[:space:]]*#/ && !seen[$0]++' images.txt > images.txt.tmp \
    && mv images.txt.tmp images.txt

if [[ ! -s images.txt ]]; then
    echo "Error: image list is empty"
    exit 1
fi

echo "Collected $(wc -l < images.txt | tr -d ' ') images to scan"

# Input file containing the list of container images
input_file="./images.txt"

# ---------------------------------------------------------------------------
# Locate and download the k3s binary to scan alongside the images
# ---------------------------------------------------------------------------
k3s_binary=""        # path to the extracted k3s binary, scanned via trivy rootfs
k3s_binary_label=""  # human label used in the report section
keep_binary_dir=""

download_release_binary() {
    local url="https://github.com/${k3s_repo}/releases/download/${release_tag_url}/k3s"
    local dir
    dir=$(mktemp -d)
    echo "Downloading k3s binary from release: $url"
    if curl -fsSL "$url" -o "$dir/k3s"; then
        chmod +x "$dir/k3s" 2>/dev/null || true
        k3s_binary="$dir/k3s"
        keep_binary_dir="$dir"
        k3s_binary_label="K3s Binary (${release_tag})"
    else
        echo "Warning: failed to download k3s binary from $url; continuing without binary scan"
        rm -rf "$dir"
    fi
}

# download_branch_binary <ref-description> [head-sha] [head-ref]
# Finds the most recent completed CI run on the branch/PR that produced a
# "k3s-amd64" artifact (uploaded by k3s-io/k3s's build-k3s.yaml reusable
# workflow), downloads it, and extracts the k3s binary.
download_branch_binary() {
    local desc="$1"
    local head_sha="$2"
    local head_ref="$3"
    local candidate_run_ids=""

    echo "Locating most recent k3s build artifact for ${desc}..."

    if [[ -n "$head_sha" ]]; then
        candidate_run_ids=$(gh run list -R "$k3s_repo" -s completed --limit 100 \
            --json databaseId,headSha --jq ".[] | select(.headSha==\"$head_sha\") | .databaseId" 2>/dev/null)
    fi
    if [[ -n "$head_ref" ]]; then
        local by_branch
        by_branch=$(gh run list -R "$k3s_repo" -b "$head_ref" -s completed --limit 50 \
            --json databaseId --jq '.[].databaseId' 2>/dev/null)
        candidate_run_ids="$candidate_run_ids $by_branch"
    fi

    candidate_run_ids=$(echo "$candidate_run_ids" | tr ' ' '\n' | grep -v '^$' | sort -rn | uniq)

    if [[ -z "$candidate_run_ids" ]]; then
        echo "Warning: no completed workflow runs found for ${desc}; continuing without binary scan"
        return
    fi

    local run_id="" artifact_name=""
    for candidate in $candidate_run_ids; do
        local names
        names=$(gh api "repos/${k3s_repo}/actions/runs/${candidate}/artifacts" --paginate \
            --jq '.artifacts[].name' 2>/dev/null)
        [[ -z "$names" ]] && continue
        # Prefer the linux/amd64 binary artifact uploaded by build-k3s.yaml.
        local match
        match=$(echo "$names" | grep -E '^k3s-amd64$' | head -1)
        [[ -z "$match" ]] && match=$(echo "$names" | grep -E '^k3s(-amd64)?$' | head -1)
        if [[ -n "$match" ]]; then
            run_id="$candidate"
            artifact_name="$match"
            break
        fi
    done

    if [[ -z "$run_id" ]]; then
        echo "Warning: no k3s binary artifact found in recent runs for ${desc}; continuing without binary scan"
        return
    fi

    echo "Found k3s binary artifact '$artifact_name' in run $run_id"
    local dir
    dir=$(mktemp -d)
    if ! gh run download "$run_id" -R "$k3s_repo" -n "$artifact_name" -D "$dir" >/dev/null 2>&1; then
        echo "Warning: failed to download artifact '$artifact_name' from run $run_id; continuing without binary scan"
        rm -rf "$dir"
        return
    fi

    # The artifact bundles dist/artifacts/. The canonical binary is named "k3s".
    local found
    found=$(find "$dir" -type f -name 'k3s' | head -1)
    if [[ -z "$found" ]]; then
        found=$(find "$dir" -type f -name 'k3s-amd64' | head -1)
    fi
    if [[ -z "$found" ]]; then
        echo "Warning: artifact did not contain a k3s binary; continuing without binary scan"
        find "$dir" -type f
        rm -rf "$dir"
        return
    fi

    # Isolate the single binary so the rootfs scan doesn't double-count the
    # duplicate "bin-k3s" symlink helper shipped in the same artifact.
    local clean
    clean=$(mktemp -d)
    cp "$found" "$clean/k3s"
    chmod +x "$clean/k3s" 2>/dev/null || true
    rm -rf "$dir"

    k3s_binary="$clean/k3s"
    keep_binary_dir="$clean"
    k3s_binary_label="K3s Binary (${desc})"
}

if [[ -n "$release_version" ]]; then
    download_release_binary
elif [[ -n "$pr_input" ]]; then
    download_branch_binary "$source_desc" "$pr_head_sha" "$pr_head_ref"
else
    download_branch_binary "branch '${branch}'" "" "$branch"
fi

# ---------------------------------------------------------------------------
# OpenVEX suppression (k3s ships rancher/mirrored-* images, so the upstream
# Rancher VEX hub still applies and trims known non-applicable findings).
# ---------------------------------------------------------------------------
if curl -fsSL https://github.com/rancher/vexhub/raw/refs/heads/main/reports/rancher.openvex.json \
    -o vex.openvex.json 2>/dev/null && [[ -s vex.openvex.json ]]; then
    if head -c 1 vex.openvex.json | grep -q '{'; then
        vex_flag="--vex vex.openvex.json"
    else
        echo "Warning: Downloaded OpenVEX file appears invalid; continuing without VEX suppression"
        rm -f vex.openvex.json
        vex_flag=""
    fi
else
    echo "Warning: Failed to download OpenVEX report; continuing without VEX suppression"
    vex_flag=""
fi

# Write markdown header and the list of images being scanned to the output file
{
    echo "# Trivy Scan Report"
    echo ""
    echo "<!-- scan-source-ref: ${source_ref} -->"
    echo "<!-- scan-source-desc: ${source_desc} -->"
    echo "## Images Scanned"
    echo ""
    while IFS= read -r image; do
        printf -- '- `%s`\n' "$image"
    done < "$input_file"
    if [[ -n "$k3s_binary" ]]; then
        echo ""
        echo "## K3s Binary"
        echo ""
        printf -- '- `%s`\n' "$k3s_binary_label"
    fi
    echo ""
} >> "$output_file"

# Track per-image CVE counts for the default-images summary section
total_critical=0
total_high=0
images_with_cves=()
images_clean=()

# Track bundle-level metrics for sqlite persistence.
bundle_total_critical=0
bundle_total_high=0
bundle_images_with_cves=0
bundle_go_stdlib_cves=0
bundle_go_module_cves=0
bundle_base_image_cves=0
bundle_images_scanned=0

# tally_severities <display-name> <scan-output-file>
# Parses trivy "Total: N (HIGH: x, CRITICAL: y)" lines and updates summary state.
tally_severities() {
    local display_name="$1"
    local scan_file="$2"
    local img_critical=0 img_high=0 h c

    while IFS= read -r line; do
        h=$(echo "$line" | sed -nE 's/.*HIGH:[[:space:]]*([0-9]+).*/\1/p')
        c=$(echo "$line" | sed -nE 's/.*CRITICAL:[[:space:]]*([0-9]+).*/\1/p')
        [[ -n "$h" ]] && img_high=$((img_high + h))
        [[ -n "$c" ]] && img_critical=$((img_critical + c))
    done < <(grep -E '^Total: [0-9]+ \(' "$scan_file")

    total_high=$((total_high + img_high))
    total_critical=$((total_critical + img_critical))

    if (( img_high + img_critical > 0 )); then
        images_with_cves+=("${display_name}|${img_critical}|${img_high}")
    else
        images_clean+=("$display_name")
    fi
}

sqlite_escape() {
    printf '%s' "$1" | sed "s/'/''/g"
}

source_attribution_python_enabled=1
source_attribution_warning_emitted=0
if ! command -v python3 >/dev/null 2>&1; then
    source_attribution_python_enabled=0
    source_attribution_warning_emitted=1
    echo "Warning: python3 not found; skipping CVE source attribution"
fi

init_metrics_db() {
    local db_dir

    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo "Warning: sqlite3 not found; skipping metrics database updates"
        return 1
    fi

    db_dir="$(dirname "$db_file")"
    mkdir -p "$db_dir"

    sqlite3 "$db_file" <<'SQL'
CREATE TABLE IF NOT EXISTS scan_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at TEXT NOT NULL,
    source_desc TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    total_images INTEGER NOT NULL,
    images_with_cves INTEGER NOT NULL,
    critical_cves INTEGER NOT NULL,
    high_cves INTEGER NOT NULL,
    go_stdlib_cves INTEGER NOT NULL,
    go_module_cves INTEGER NOT NULL,
    base_image_cves INTEGER NOT NULL,
    optional_total_images INTEGER NOT NULL DEFAULT 0,
    optional_images_with_cves INTEGER NOT NULL DEFAULT 0,
    optional_critical_cves INTEGER NOT NULL DEFAULT 0,
    optional_high_cves INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_scan_metrics_scanned_at ON scan_metrics(scanned_at);
CREATE INDEX IF NOT EXISTS idx_scan_metrics_source_ref_scanned_at
    ON scan_metrics(source_ref, scanned_at);
CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_metrics_run_signature
    ON scan_metrics(
        scanned_at,
        source_ref,
        total_images,
        images_with_cves,
        critical_cves,
        high_cves,
        go_stdlib_cves,
        go_module_cves,
        base_image_cves
    );

-- Per-CVE identities captured per scan run. Enables precise fix tracking:
-- a CVE present for a source in one scan but absent in the next was resolved
-- on the later scan's date. Linked to the aggregate row via scan_id.
CREATE TABLE IF NOT EXISTS scan_cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scan_metrics(id),
    scanned_at TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'default',
    image TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    package TEXT NOT NULL DEFAULT '',
    installed_version TEXT NOT NULL DEFAULT '',
    fixed_version TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_scan_cves_scan_id ON scan_cves(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_cves_cve_id ON scan_cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_scan_cves_source_ref_scanned_at
    ON scan_cves(source_ref, scanned_at);
CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_cves_identity
    ON scan_cves(scan_id, image, cve_id, package, installed_version);
SQL
}

classify_cve_sources() {
    local scan_json="$1"
    local result

    if (( source_attribution_python_enabled == 0 )); then
        echo "0|0|0"
        return
    fi

    if [[ ! -s "$scan_json" ]]; then
        if (( source_attribution_warning_emitted == 0 )); then
            echo "Warning: missing Trivy JSON results; CVE source attribution will default to zero counts" >&2
            source_attribution_warning_emitted=1
        fi
        echo "0|0|0"
        return
    fi

    if ! result="$(python3 - "$scan_json" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    print("0|0|0")
    sys.exit(0)

counts = {"go_stdlib": 0, "go_module": 0, "base_image": 0}
for result in data.get("Results", []):
    result_class = (result.get("Class") or "").lower()
    result_type = (result.get("Type") or "").lower()

    for vuln in result.get("Vulnerabilities") or []:
        if vuln.get("Severity") not in {"HIGH", "CRITICAL"}:
            continue

        pkg_name = (vuln.get("PkgName") or "").lower()

        if result_class == "os-pkgs":
            counts["base_image"] += 1
            continue

        if pkg_name in {"stdlib", "go"}:
            counts["go_stdlib"] += 1
            continue

        if result_type in {"gomod", "gobinary"}:
            counts["go_module"] += 1

print(
    f"{counts['go_stdlib']}|{counts['go_module']}|{counts['base_image']}"
)
PY
)"; then
        if (( source_attribution_warning_emitted == 0 )); then
            echo "Warning: failed to classify CVE sources from Trivy JSON; defaulting attribution to zero counts" >&2
            source_attribution_warning_emitted=1
        fi
        echo "0|0|0"
        return
    fi

    echo "$result"
}

# Accumulator file for per-CVE rows captured across every scan path. Populated by
# collect_cve_rows and flushed into the scan_cves table alongside scan_metrics.
cve_rows_file="$(mktemp)"

# collect_cve_rows <scan-json> <image> [scope]
# Appends one tab-separated row per CRITICAL/HIGH vulnerability found in the
# Trivy JSON to $cve_rows_file. Columns: scope, image, cve_id, severity,
# package, installed_version, fixed_version.
collect_cve_rows() {
    local scan_json="$1"
    local image="$2"
    local scope="${3:-default}"

    if (( source_attribution_python_enabled == 0 )); then
        return
    fi

    if [[ ! -s "$scan_json" ]]; then
        return
    fi

    python3 - "$scan_json" "$image" "$scope" >> "$cve_rows_file" <<'PY'
import json
import sys

scan_json, image, scope = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    with open(scan_json, "r", encoding="utf-8") as f:
        data = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    sys.exit(0)


def clean(value):
    return str(value or "").replace("\t", " ").replace("\n", " ").replace("\r", " ")


seen = set()
for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities") or []:
        severity = vuln.get("Severity")
        if severity not in {"HIGH", "CRITICAL"}:
            continue

        cve_id = clean(vuln.get("VulnerabilityID"))
        if not cve_id:
            continue

        package = clean(vuln.get("PkgName"))
        installed = clean(vuln.get("InstalledVersion"))

        key = (cve_id, package, installed)
        if key in seen:
            continue
        seen.add(key)

        fixed = clean(vuln.get("FixedVersion"))
        print(
            "\t".join(
                [clean(scope), clean(image), cve_id, clean(severity), package, installed, fixed]
            )
        )
PY
}

# scan_target <trivy-target-args...> with a display label set in $scan_label
# Runs Trivy, appends a results section, and rolls findings into the totals.
run_scan_section() {
    local label="$1"
    shift
    local scan_tmp scan_json_tmp
    scan_tmp=$(mktemp)
    scan_json_tmp=$(mktemp)

    trivy "$@" $vex_flag --severity CRITICAL,HIGH --format json > "$scan_json_tmp" 2>/dev/null
    trivy convert --format table "$scan_json_tmp" > "$scan_tmp" 2>/dev/null
    {
        echo "## Scan Results: ${label}"
        echo ""
        echo '```text'
        cat "$scan_tmp"
        echo '```'
        echo ""
    } >> "$output_file"

    tally_severities "$label" "$scan_tmp"
    local source_breakdown
    source_breakdown=$(classify_cve_sources "$scan_json_tmp")
    collect_cve_rows "$scan_json_tmp" "$label" "default"

    local img_go_stdlib img_go_module img_base_image
    IFS='|' read -r img_go_stdlib img_go_module img_base_image <<< "$source_breakdown"
    bundle_go_stdlib_cves=$((bundle_go_stdlib_cves + img_go_stdlib))
    bundle_go_module_cves=$((bundle_go_module_cves + img_go_module))
    bundle_base_image_cves=$((bundle_base_image_cves + img_base_image))

    local img_critical img_high
    img_critical=$(grep -E '^Total: [0-9]+ \(' "$scan_tmp" | sed -nE 's/.*CRITICAL:[[:space:]]*([0-9]+).*/\1/p' | awk '{s+=$1} END{print s+0}')
    img_high=$(grep -E '^Total: [0-9]+ \(' "$scan_tmp" | sed -nE 's/.*HIGH:[[:space:]]*([0-9]+).*/\1/p' | awk '{s+=$1} END{print s+0}')
    bundle_total_critical=$((bundle_total_critical + img_critical))
    bundle_total_high=$((bundle_total_high + img_high))
    if (( img_critical + img_high > 0 )); then
        bundle_images_with_cves=$((bundle_images_with_cves + 1))
    fi

    rm -f "$scan_tmp" "$scan_json_tmp"
}

# Loop through each image in the input file
while IFS= read -r image; do
    image="${image#"${image%%[![:space:]]*}"}"
    image="${image%"${image##*[![:space:]]}"}"
    if [[ -z "$image" || "$image" == \#* ]]; then
        continue
    fi

    echo "Scanning image: $image"
    bundle_images_scanned=$((bundle_images_scanned + 1))
    run_scan_section "$image" image "$image"
done < "$input_file"

# Scan the k3s binary itself, if we managed to fetch one.
if [[ -n "$k3s_binary" ]]; then
    echo "Scanning k3s binary: $k3s_binary"
    bundle_images_scanned=$((bundle_images_scanned + 1))
    run_scan_section "$k3s_binary_label" rootfs "$(dirname "$k3s_binary")"
    if [[ -n "$keep_binary_dir" ]]; then
        rm -rf "$keep_binary_dir"
    fi
fi

# Append a markdown summary section to the end of the report
{
    echo "## Summary"
    echo ""
    echo "### CVEs by Severity"
    echo ""
    echo "| Severity | Count |"
    echo "| --- | ---: |"
    echo "| CRITICAL | ${total_critical} |"
    echo "| HIGH | ${total_high} |"
    echo "| **Total** | **$((total_critical + total_high))** |"
    echo ""

    echo "### Images with CVEs (${#images_with_cves[@]})"
    echo ""
    if (( ${#images_with_cves[@]} == 0 )); then
        echo "_None_"
    else
        echo "| Image | CRITICAL | HIGH |"
        echo "| --- | ---: | ---: |"
        for entry in "${images_with_cves[@]}"; do
            name="${entry%%|*}"
            rest="${entry#*|}"
            crit="${rest%%|*}"
            high="${rest#*|}"
            printf '| `%s` | %d | %d |\n' "$name" "$crit" "$high"
        done
    fi
    echo ""

    echo "### CVE-free Images (${#images_clean[@]})"
    echo ""
    if (( ${#images_clean[@]} == 0 )); then
        echo "_None_"
    else
        for name in "${images_clean[@]}"; do
            printf -- '- `%s`\n' "$name"
        done
    fi
    echo ""
} >> "$output_file"

echo "Trivy scan completed. Reports are saved in $output_file."

if init_metrics_db; then
    scanned_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    source_desc_db="$(sqlite_escape "$source_desc")"
    source_ref_db="$(sqlite_escape "${source_ref}")"
    total_images=$(wc -l < "$input_file" | tr -d ' ')
    if [[ -n "$k3s_binary" ]]; then
        total_images=$((total_images + 1))
    fi

    sqlite3 "$db_file" <<SQL
INSERT OR IGNORE INTO scan_metrics (
    scanned_at,
    source_desc,
    source_ref,
    total_images,
    images_with_cves,
    critical_cves,
    high_cves,
    go_stdlib_cves,
    go_module_cves,
    base_image_cves,
    optional_total_images,
    optional_images_with_cves,
    optional_critical_cves,
    optional_high_cves
) VALUES (
    '${scanned_at}',
    '${source_desc_db}',
    '${source_ref_db}',
    ${total_images},
    ${bundle_images_with_cves},
    ${total_critical},
    ${total_high},
    ${bundle_go_stdlib_cves},
    ${bundle_go_module_cves},
    ${bundle_base_image_cves},
    0,
    0,
    0,
    0
);
SQL
    if [[ "$(sqlite3 "$db_file" 'SELECT changes();')" -gt 0 ]]; then
        echo "Scan metrics written to $db_file"
    else
        echo "Scan metrics already recorded for this run signature; skipped duplicate insert"
    fi

    # Persist the individual CVE identities captured during the scan, linked to
    # this run's scan_metrics row. Idempotent via uq_scan_cves_identity.
    if [[ -s "$cve_rows_file" ]]; then
        scan_id="$(sqlite3 "$db_file" \
            "SELECT id FROM scan_metrics WHERE scanned_at='${scanned_at}' AND source_ref='${source_ref_db}' ORDER BY id DESC LIMIT 1;")"
        if [[ -n "$scan_id" ]] && command -v python3 >/dev/null 2>&1; then
            if python3 - "$cve_rows_file" "$scan_id" "$scanned_at" "$source_ref" <<'PY' | sqlite3 "$db_file"
import sys

rows_file, scan_id, scanned_at, source_ref = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]


def q(value):
    return "'" + str(value).replace("'", "''") + "'"


with open(rows_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 7:
            continue
        scope, image, cve_id, severity, package, installed, fixed = fields
        print(
            "INSERT OR IGNORE INTO scan_cves "
            "(scan_id, scanned_at, source_ref, scope, image, cve_id, severity, "
            "package, installed_version, fixed_version) VALUES ("
            + ", ".join(
                [
                    str(int(scan_id)),
                    q(scanned_at),
                    q(source_ref),
                    q(scope),
                    q(image),
                    q(cve_id),
                    q(severity),
                    q(package),
                    q(installed),
                    q(fixed),
                ]
            )
            + ");"
        )
PY
            then
                cve_row_count="$(sqlite3 "$db_file" "SELECT count(*) FROM scan_cves WHERE scan_id=${scan_id};")"
                echo "Recorded ${cve_row_count} per-CVE rows for scan ${scan_id} in $db_file"
            else
                echo "Warning: failed to persist per-CVE rows to $db_file" >&2
            fi
        fi
    fi
fi

rm -f "$cve_rows_file"

if [[ -n "$gist_title" ]]; then
    echo "Uploading results to GitHub Gist..."
    gist_url=$(gh gist create --public --desc "$gist_title" --filename "$output_file" "$output_file" 2>&1)
    if [[ $? -eq 0 ]]; then
        echo "Gist created: $gist_url"

        # If both PR and gist are provided, add a comment to the PR with the gist link
        if [[ -n "$pr_number" ]]; then
            echo "Adding comment to PR #${pr_number} with gist link..."
            if gh pr comment "$pr_number" -R "$k3s_repo" --body "Trivy scan results: ${gist_url}"; then
                echo "Comment added to PR #${pr_number}"
            else
                echo "Warning: Failed to add comment to PR #${pr_number}"
            fi
        fi
    else
        echo "Error creating gist: $gist_url"
        exit 1
    fi
fi
