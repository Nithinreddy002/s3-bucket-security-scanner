import boto3
import streamlit as st
from botocore.exceptions import ClientError, NoCredentialsError

from scanner import scan_bucket

TARGET_BUCKETS = ["secure-bucket-nithin", "public-bucket-nithin"]

st.set_page_config(page_title="S3 Security Scanner", layout="wide")
st.title("S3 Bucket Security Scanner")

s3 = boto3.client("s3")


def run_scan():
    response = s3.list_buckets()
    buckets = response.get("Buckets", [])
    results = []
    for b in buckets:
        name = b["Name"]
        if name in TARGET_BUCKETS:
            results.append(scan_bucket(name))
    return results


if st.button("Run Scan"):
    with st.spinner("Scanning buckets…"):
        try:
            results = run_scan()
            if not results:
                st.warning("No matching buckets found. Expected: " + ", ".join(TARGET_BUCKETS))
            else:
                for row in results:
                    risk = row["risk"]
                    with st.container():
                        st.subheader(row["bucket_name"])
                        c1, c2, c3, c4, c5 = st.columns(5)
                        c1.metric("Public policy", str(row["public_policy"]))
                        c2.metric("Public ACL", str(row["public_acl"]))
                        c3.metric("Encryption", str(row["encryption"]))
                        c4.metric("Versioning", row["versioning"])
                        c5.metric("Risk", risk)
                        st.divider()
        except NoCredentialsError:
            st.error("AWS credentials not found. Configure with `aws configure` or environment variables.")
        except ClientError as e:
            st.error(f"AWS error: {e}")
