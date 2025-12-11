#!/bin/bash

################################################################################
# run_local_scans_from_uris.sh
#
# Variant of run_local_scans_experiment.sh that accepts image URIs from
# command-line arguments or an environment array `IMAGE_URIS`.
#
# Usage examples:
#  ./run_local_scans_from_uris.sh nginx:latest alpine:latest
#  IMAGE_URIS=(nginx:latest alpine:latest) ./run_local_scans_from_uris.sh
#
################################################################################

set -o pipefail

# Single-trial run: this script always performs one scan per image. The
# previous `-n`/trials option was removed to simplify local usage.
TRIAL_ID=1

# If arguments provided, use them as the image list. Otherwise, try to use
# the environment array IMAGE_URIS (e.g., IMAGE_URIS=(img1 img2) ./script).
if [ "$#" -gt 0 ]; then
    IMAGE_LIST=("$@")
else
    if [ -z "${IMAGE_URIS+x}" ]; then
        echo "ERROR: No images provided. Pass as arguments or set IMAGE_URIS array." >&2
        exit 1
    fi
    # If IMAGE_URIS is a single string, convert to array safely
    if [ "$(declare -p IMAGE_URIS 2>/dev/null | sed -n 's/^.*=//p')" = "" ]; then
        echo "ERROR: IMAGE_URIS environment variable is empty." >&2
        exit 1
    fi
    # Copy to local array
    IMAGE_LIST=("${IMAGE_URIS[@]}")
fi

OUTPUT_DIR="local_scan_results"
METRICS_LOG="$OUTPUT_DIR/summary_metrics.csv"

# Ensure the output directory exists (create if missing)
if [ ! -d "$OUTPUT_DIR" ]; then
    mkdir -p "$OUTPUT_DIR"
fi

# Also ensure a top-level reports folder exists for convenience
mkdir -p "$OUTPUT_DIR/reports"

if [ ! -f "$METRICS_LOG" ]; then
    echo "trial,scanTimestamp,repoName,imageTag,imageDigest,status,scanDurationMs,criticalCount,highCount,mediumCount,lowCount,totalVulns,reportFile" > "$METRICS_LOG"
fi

echo "Starting local scan baseline..."
echo "Running single trial for ${#IMAGE_LIST[@]} image(s)"
echo "Results will be stored in $OUTPUT_DIR"

for image_name in "${IMAGE_LIST[@]}"; do
        if [ -z "$image_name" ]; then
            continue
        fi

        echo "--- Processing: $image_name (Trial $TRIAL_ID) ---"

        echo "Pulling $image_name..."
        if ! docker pull "$image_name"; then
            echo "ERROR: Failed to pull $image_name. Skipping."
            # repoName,imageTag
            repo_name=$(echo "$image_name" | cut -d':' -f1)
            image_tag=$(echo "$image_name" | cut -d':' -f2)
            if [ "$repo_name" == "$image_tag" ]; then
                image_tag="latest"
            fi
            echo "$trial,$(date +%s),$repo_name,$image_tag,,FAILED,0,0,0,0,0,0," >> "$METRICS_LOG"
            continue
        fi

        image_digest=$(docker image inspect "$image_name" --format '{{index .RepoDigests 0}}' 2>/dev/null | cut -d'@' -f2 || true)
        if [ -z "$image_digest" ]; then
            image_digest=$(docker image inspect "$image_name" --format '{{.Id}}' 2>/dev/null || true)
            echo "Warning: Could not find RepoDigest for $image_name, using ImageID: $image_digest"
        fi

        repo_name=$(echo "$image_name" | cut -d':' -f1)
        image_tag=$(echo "$image_name" | cut -d':' -f2)
        if [ "$repo_name" == "$image_tag" ]; then
            image_tag="latest"
        fi

        report_dir="$OUTPUT_DIR/reports/$repo_name/$image_tag"
        mkdir -p "$report_dir"
        timestamp=$(date +%Y%m%d%H%M%S)
        local_report_json="$report_dir/report_${timestamp}.json"

        echo "Scanning $image_name..."
        start_time=$(date +%s%N)

        if ! trivy image --format json --output "$local_report_json" "$image_name"; then
            echo "ERROR: Trivy scan failed for $image_name. Skipping."
            echo "$TRIAL_ID,$(date +%s),$repo_name,$image_tag,$image_digest,FAILED,0,0,0,0,0,0,$local_report_json" >> "$METRICS_LOG"
            continue
        fi

        end_time=$(date +%s%N)
        duration_ms=$(( (end_time - start_time) / 1000000 ))

        echo "Parsing report $local_report_json..."
        counts=$(jq -r '
                [.Results[]? .Vulnerabilities[]? .Severity] as $s |
                [ ($s|map(select(.=="CRITICAL"))|length),
                    ($s|map(select(.=="HIGH"))|length),
                    ($s|map(select(.=="MEDIUM"))|length),
                    ($s|map(select(.=="LOW"))|length),
                    ($s|length)
                ] | @tsv
        ' "$local_report_json" 2>/dev/null || echo -e "0\t0\t0\t0\t0")

        read -r critical_count high_count medium_count low_count total_vulns <<<"$counts"
        critical_count=${critical_count:-0}
        high_count=${high_count:-0}
        medium_count=${medium_count:-0}
        low_count=${low_count:-0}
        total_vulns=${total_vulns:-0}

        scan_timestamp=$(date +%s)
        echo "$TRIAL_ID,$scan_timestamp,$repo_name,$image_tag,$image_digest,SUCCESS,$duration_ms,$critical_count,$high_count,$medium_count,$low_count,$total_vulns,$local_report_json" >> "$METRICS_LOG"

        echo "Scan complete. Duration: $duration_ms ms. Counts: C:$critical_count, H:$high_count, M:$medium_count, L:$low_count (Total:$total_vulns)"

done

echo "--- All scans complete. ---"
echo "Summary metrics logged to $METRICS_LOG"
echo "Full JSON reports are in $OUTPUT_DIR/reports/"

exit 0
