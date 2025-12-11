import boto3
import json
import datetime
import time

ecr = boto3.client("ecr")
s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")

S3_BUCKET = "local-baseline-vuln-scan-reports"
DDB_TABLE = "ECR_Vulnerabilities"
REPO = "image-vulnerability-scan"

table = dynamodb.Table(DDB_TABLE)


# Helper to convert datetime and other non-serializable types
def make_json_safe(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [make_json_safe(v) for v in obj]
    return obj


def lambda_handler(event, context):

    # 1. List all images in repository
    images = ecr.list_images(repositoryName=REPO, maxResults=100)["imageIds"]
    final_report = {}

    for img in images:
        tag = img.get("imageTag", "untagged")
        print(f"Scanning image: {tag}")

        # ---------------------------------------------------------------------
        # 2. Trigger image scan + measure scan time
        # ---------------------------------------------------------------------
        scan_start = datetime.datetime.utcnow()

        try:
            ecr.start_image_scan(repositoryName=REPO, imageId=img)
            print(f"Triggered scan for {tag}")
        except Exception as e:
            print(f"Error triggering scan for {tag}: {e}")

        # Poll for scan to complete (max ~100 seconds)
        for _ in range(20):
            status_resp = ecr.describe_image_scan_findings(
                repositoryName=REPO, imageId=img
            )
            status = status_resp.get("imageScanStatus", {}).get("status")

            if status == "COMPLETE":
                print(f"Scan completed for {tag}")
                break

            print(f"Scan still running for {tag}...waiting")
            time.sleep(5)

        scan_end = datetime.datetime.utcnow()
        scan_duration = (scan_end - scan_start).total_seconds()

        # ---------------------------------------------------------------------
        # 3. Fetch final scan findings
        # ---------------------------------------------------------------------
        scan = ecr.describe_image_scan_findings(repositoryName=REPO, imageId=img)
        findings = scan.get("imageScanFindings", {})
        findings = make_json_safe(findings)

        final_report[tag] = {
            "scan_time_seconds": scan_duration,
            "findings": findings
        }

        # ---------------------------------------------------------------------
        # 4. Store scan-time file in S3
        # ---------------------------------------------------------------------
        timestamp = datetime.datetime.utcnow().isoformat()
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=f"{tag}/scan-time-{timestamp}.json",
            Body=json.dumps(
                {"image": tag, "scan_time_seconds": scan_duration, "timestamp": timestamp},
                indent=2
            )
        )

        # ---------------------------------------------------------------------
        # 5. Store full scan findings in S3
        # ---------------------------------------------------------------------
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=f"{tag}/report-{timestamp}.json",
            Body=json.dumps(findings, indent=2)
        )

        # ---------------------------------------------------------------------
        # 6. Store individual CVEs in DynamoDB
        # ---------------------------------------------------------------------
        for f in findings.get("findings", []):
            try:
                table.put_item(
                    Item={
                        "ImageTag": tag,
                        "CVE_ID": f.get("name", "UNKNOWN"),
                        "Severity": f.get("severity", "UNKNOWN"),
                        "Package": f.get("packageName", "N/A"),
                        "Version": f.get("packageVersion", "N/A"),
                        "Description": f.get("description", "N/A"),
                        "URL": f.get("uri", "N/A"),
                        "Timestamp": timestamp
                    }
                )
            except Exception as db_err:
                print(f"Failed to store CVE in DB for {tag}: {db_err}")

    # -------------------------------------------------------------------------
    # 7. Return combined scan report for all images
    # -------------------------------------------------------------------------
    return {
        "statusCode": 200,
        "body": json.dumps(final_report, indent=2)
    }