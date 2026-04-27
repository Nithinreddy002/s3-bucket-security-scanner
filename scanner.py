import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError

# Create S3 client
s3 = boto3.client("s3")


def get_public_access_block(bucket_name):
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        return response["PublicAccessBlockConfiguration"]
    except ClientError:
        return None


def get_bucket_policy(bucket_name):
    try:
        response = s3.get_bucket_policy(Bucket=bucket_name)
        return json.loads(response["Policy"])
    except ClientError:
        return None


def get_bucket_encryption(bucket_name):
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
        return True
    except ClientError:
        return False


def get_bucket_acl(bucket_name):
    try:
        response = s3.get_bucket_acl(Bucket=bucket_name)
        return response["Grants"]
    except ClientError:
        return None


def get_bucket_versioning(bucket_name):
    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        status = response.get("Status")

        if status:
            return status
        else:
            return "Disabled"

    except ClientError:
        return "Unknown"


def is_bucket_public(policy):
    if not policy:
        return False

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        effect = statement.get("Effect")
        principal = statement.get("Principal")
        actions = statement.get("Action")

        if isinstance(actions, str):
            actions = [actions]

        if effect == "Allow" and principal == "*":
            if "s3:GetObject" in actions or "s3:*" in actions:
                return True

    return False


def is_acl_public(grants):
    if not grants:
        return False

    for grant in grants:
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")

        if "AllUsers" in uri:
            return True
        if "AuthenticatedUsers" in uri:
            return True

    return False


def calculate_risk(public_policy, public_acl, encryption_enabled, public_access_block, versioning_status):
    if public_policy or public_acl:
        return "HIGH"
    elif not encryption_enabled:
        return "MEDIUM"
    elif public_access_block is None:
        return "MEDIUM"
    elif versioning_status != "Enabled":
        return "MEDIUM"
    else:
        return "LOW"


def save_report(data):
    try:
        with open("s3_report.json", "w") as file:
            json.dump(data, file, indent=4)
        print("\nReport saved as s3_report.json")
    except Exception as e:
        print("Error saving report:", e)


def scan_bucket(bucket_name):
    print("\n" + "=" * 70)
    print(f"Checking bucket: {bucket_name}")

    public_access_block = get_public_access_block(bucket_name)
    bucket_policy = get_bucket_policy(bucket_name)
    encryption_enabled = get_bucket_encryption(bucket_name)
    bucket_acl = get_bucket_acl(bucket_name)
    versioning_status = get_bucket_versioning(bucket_name)

    public_policy_found = is_bucket_public(bucket_policy)
    public_acl_found = is_acl_public(bucket_acl)
    risk_level = calculate_risk(
        public_policy_found,
        public_acl_found,
        encryption_enabled,
        public_access_block,
        versioning_status,
    )

    return {
        "bucket_name": bucket_name,
        "public_policy": public_policy_found,
        "public_acl": public_acl_found,
        "encryption": encryption_enabled,
        "versioning": versioning_status,
        "risk": risk_level,
    }


def main():
    try:
        response = s3.list_buckets()
        buckets = response["Buckets"]

        if not buckets:
            print("No S3 buckets found in your AWS account.")
            return

        print("Starting S3 bucket security scan...")

        all_results = []

        for bucket in buckets:
            bucket_name = bucket["Name"]
            if bucket_name in ["secure-bucket-nithin", "public-bucket-nithin"]:
                result = scan_bucket(bucket_name)
                all_results.append(result)

        save_report(all_results)

        print("\nScan completed successfully.")

    except NoCredentialsError:
        print("AWS credentials not found. Please run 'aws configure' first.")
    except ClientError as e:
        print("Error connecting to AWS:", e)


if __name__ == "__main__":
    main()
