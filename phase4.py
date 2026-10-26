
import boto3
from pathlib import Path
from botocore.exceptions import ClientError, NoCredentialsError

BUCKET_NAME = "aayush-secure-storage-2026-unique"
AWS_REGION = "eu-north-1"

BASE_DIR = Path(__file__).resolve().parent
DOWNLOAD_DIR = BASE_DIR / "cloud_downloads"

S3_PREFIX = "encrypted_blocks/downloads (4)_20261025_193647_356828/"


def download_encrypted_files():
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

    s3 = boto3.client("s3", region_name=AWS_REGION)

    try:
        response = s3.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=S3_PREFIX
        )

        objects = response.get("Contents", [])

        if not objects:
            print("No files found in the specified S3 folder.")
            return

        for obj in objects:
            key = obj["Key"]

            # Keep downloaded files inside the download directory.
            relative_path = key[len(S3_PREFIX):]

            if not relative_path:
                continue

            local_path = DOWNLOAD_DIR / relative_path
            local_path.parent.mkdir(parents=True, exist_ok=True)

            print(f"Downloading: {key}")

            s3.download_file(
                BUCKET_NAME,
                key,
                str(local_path)
            )

            print(f"Downloaded: {local_path}")

        print("\nAll encrypted files downloaded successfully!")
        print(f"Location: {DOWNLOAD_DIR}")

    except NoCredentialsError:
        print("AWS credentials not found. Run: aws configure")

    except ClientError as error:
        print(f"AWS error: {error}")


if __name__ == "__main__":
    download_encrypted_files()
