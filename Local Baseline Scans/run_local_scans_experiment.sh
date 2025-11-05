#!/bin/bash

################################################################################
# run_local_scans.sh
#
# Reads a list of container images from `images.txt` and runs multiple
# Trivy scan trials on each, collecting metrics and reports.
#
# PREREQUISITES:
# - docker (and docker daemon must be running)
# - trivy (installed and in your PATH)
# - jq (installed and in your PATH)
#
################################################################################

# --- Configuration ---

# The file containing image names, one per line (e.g., nginx:latest)
IMAGE_LIST_FILE="images.txt"

# The number of trials to run for each image (default can be overridden with -n)
NUM_TRIALS=3

# Parse command-line options. Usage: ./run_local_scans.sh [-n NUM_TRIALS]
while getopts ":n:h" opt; do
    case $opt in
        n)
            # Ensure integer
            if ! [[ "$OPTARG" =~ ^[0-9]+$ ]]; then
                echo "ERROR: -n requires a positive integer." >&2
                exit 1
            fi
            NUM_TRIALS="$OPTARG"
            ;;
        h)
            echo "Usage: $0 [-n NUM_TRIALS]"
            exit 0
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
        :) 
            echo "Option -$OPTARG requires an argument." >&2
            exit 1
            ;;
    esac
done
shift $((OPTIND -1))

# Main directory to store all scan results
OUTPUT_DIR="local_scan_results"

# The summary CSV file that will mimic the DynamoDB structure 
METRICS_LOG="$OUTPUT_DIR/summary_metrics.csv"

# --- Script ---

# Create the output directory
mkdir -p "$OUTPUT_DIR"

# Write the CSV header if the file doesn't exist
if [ ! -f "$METRICS_LOG" ]; then
    echo "trial,scanTimestamp,repoName,imageTag,imageDigest,status,scanDurationMs,criticalCount,highCount,mediumCount,lowCount,totalVulns,reportFile" > "$METRICS_LOG"
fi

# Check for the image list file
if [ ! -f "$IMAGE_LIST_FILE" ]; then
    echo "ERROR: Image list file not found at '$IMAGE_LIST_FILE'"
    exit 1
fi

echo "Starting local scan baseline..."
echo "Running $NUM_TRIALS trial(s) for each image in $IMAGE_LIST_FILE"
echo "Results will be stored in $OUTPUT_DIR"

# Loop for each trial 
for trial in $(seq 1 $NUM_TRIALS); do
    
    echo "=============== STARTING TRIAL $trial / $NUM_TRIALS ==============="
    
    # Read the image list file line by line
    while IFS= read -r image_name || [ -n "$image_name" ]; do
        
        # Skip empty lines
        if [ -z "$image_name" ]; then continue; fi
        
        echo "--- Processing: $image_name (Trial $trial) ---"

        # 1. Pull image to ensure it's local and up-to-date
        echo "Pulling $image_name..."
        if ! docker pull "$image_name"; then
            echo "ERROR: Failed to pull $image_name. Skipping."
            echo "$trial,$(date +%s),${image_name//:/,},,FAILED,0,0,0,0,0,0," >> "$METRICS_LOG"
            continue
        fi

        # 2. Get image metadata
        # Use docker inspect to get theRepoDigest and parse it
        image_digest=$(docker image inspect "$image_name" --format '{{index .RepoDigests 0}}' | cut -d'@' -f2)
        if [ -z "$image_digest" ]; then
            # Fallback to ImageID if no RepoDigest (less ideal, but stable)
            image_digest=$(docker image inspect "$image_name" --format '{{.Id}}')
            echo "Warning: Could not find RepoDigest, using ImageID: $image_digest"
        fi
        
        # Parse Repo and Tag from the name
        repo_name=$(echo "$image_name" | cut -d':' -f1)
        image_tag=$(echo "$image_name" | cut -d':' -f2)
        if [ "$repo_name" == "$image_tag" ]; then
            image_tag="latest" # Handle images specified without a tag (e.g., 'alpine')
        fi

        # 3. Create structured directory for this trial's report
        # Store reports in the image tag directory and name each file with the trial number
        report_dir="$OUTPUT_DIR/reports/$repo_name/$image_tag"
        mkdir -p "$report_dir"
        local_report_json="$report_dir/trial_${trial}_report.json"
        
        # 4. Run the scan and capture wall-clock time [cite: 76]
        echo "Scanning $image_name..."
        start_time=$(date +%s%N) # Start time in nanoseconds
        
        # Run Trivy scan, save JSON report
        if ! trivy image --format json --output "$local_report_json" "$image_name"; then
            echo "ERROR: Trivy scan failed for $image_name. Skipping."
            echo "$trial,$(date +%s),$repo_name,$image_tag,$image_digest,FAILED,0,0,0,0,0,0,$local_report_json" >> "$METRICS_LOG"
            continue
        fi
        
        end_time=$(date +%s%N) # End time in nanoseconds
        duration_ms=$(( (end_time - start_time) / 1000000 )) # Duration in milliseconds 

        # 5. Parse JSON report for metrics using jq
        echo "Parsing report $local_report_json..."
        
        # This jq command safely counts severities, even if a severity is not present
        counts=$(jq -r '
                [.Results[]? .Vulnerabilities[]? .Severity] as $s |
                [ ($s|map(select(.=="CRITICAL"))|length),
                    ($s|map(select(.=="HIGH"))|length),
                    ($s|map(select(.=="MEDIUM"))|length),
                    ($s|map(select(.=="LOW"))|length),
                    ($s|length)
                ] | @tsv
        ' "$local_report_json")
        
        # Read counts into variables
        read -r critical_count high_count medium_count low_count total_vulns <<<"$counts"

        # 6. Log metrics to CSV (matches DynamoDB schema )
        scan_timestamp=$(date +%s)
        echo "$trial,$scan_timestamp,$repo_name,$image_tag,$image_digest,SUCCESS,$duration_ms,$critical_count,$high_count,$medium_count,$low_count,$total_vulns,$local_report_json" >> "$METRICS_LOG"

        echo "Scan complete. Duration: $duration_ms ms. Counts: C:$critical_count, H:$high_count, M:$medium_count, L:$low_count (Total:$total_vulns)"

    done < "$IMAGE_LIST_FILE"
    
    echo "=============== TRIAL $trial COMPLETE ==============="
    
done

echo "--- All scans complete. ---"
echo "Summary metrics logged to $METRICS_LOG"
echo "Full JSON reports are in $OUTPUT_DIR/reports/"
