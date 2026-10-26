
import boto3
from pathlib import Path
from botocore.exceptions import ClientError, NoCredentialsError

BUCKET_NAME = "aayush-secure-storage-2026-unique"
AWS_REGION = "eu-north-1"

BASE_DIR = Path(__file__).resolve().parent
ENCRYPTED_DIR = BASE_DIR / "encrypted_blocks"


def upload_encrypted_files():
    if not ENCRYPTED_DIR.exists():
        print("ERROR: encrypted_blocks folder not found.")
        return

    # Find encrypted blocks and manifests inside nested folders.
    files = [
        file for file in ENCRYPTED_DIR.rglob("*")
        if file.is_file()
        and (file.suffix == ".enc" or file.name == "manifest.json")
    ]

    if not files:
        print("No encrypted blocks or manifest.json found.")
        return

    s3 = boto3.client("s3", region_name=AWS_REGION)

    print(f"Uploading files to S3 bucket: {BUCKET_NAME}")

    try:
        for file_path in files:
            relative_path = file_path.relative_to(ENCRYPTED_DIR)
            object_key = f"encrypted_blocks/{relative_path.as_posix()}"

            print(f"Uploading: {relative_path}")

            s3.upload_file(
                str(file_path),
                BUCKET_NAME,
                object_key
            )

            print(f"SUCCESS: {object_key}")

        print("\nAll encrypted files uploaded successfully!")

    except NoCredentialsError:
        print("ERROR: AWS credentials not found. Run: aws configure")

    except ClientError as error:
        print(f"AWS ERROR: {error}")


if __name__ == "__main__":
    upload_encrypted_files()
