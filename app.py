import uuid
import boto3

from pathlib import Path
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from botocore.exceptions import ClientError, NoCredentialsError

from phase2 import encrypt_file, decrypt_file

app = Flask(__name__)

# Project configuration
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
ENCRYPTED_DIR = BASE_DIR / "encrypted_blocks"
CLOUD_DOWNLOAD_DIR = BASE_DIR / "cloud_downloads"

BUCKET_NAME = "aayush-secure-storage-2026-unique"
AWS_REGION = "eu-north-1"

# Maximum upload size: 100 MB
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

# Create required directories
for folder in [UPLOAD_DIR, ENCRYPTED_DIR, CLOUD_DOWNLOAD_DIR]:
    folder.mkdir(parents=True, exist_ok=True)


def get_s3_client():
    return boto3.client("s3", region_name=AWS_REGION)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    uploaded_file = request.files.get("file")
    block_size = request.form.get("block_size", "1")

    # Validate file selection
    if not uploaded_file or not uploaded_file.filename:
        return render_template(
            "index.html",
            error="Please select a file first."
        )

    filename = secure_filename(uploaded_file.filename)

    if not filename:
        return render_template(
            "index.html",
            error="Please choose a valid filename."
        )

    source_path = None
    temp_upload_dir = None

    try:
        # Validate block size
        try:
            block_size = int(block_size)
        except (TypeError, ValueError):
            return render_template(
                "index.html",
                error="Invalid block size. Choose 1, 2, 5, or 10 MB."
            )

        if block_size not in (1, 2, 5, 10):
            return render_template(
                "index.html",
                error="Invalid block size. Choose 1, 2, 5, or 10 MB."
            )

        # Create a unique temporary directory for every upload
        temp_upload_dir = UPLOAD_DIR / uuid.uuid4().hex
        temp_upload_dir.mkdir(parents=True, exist_ok=False)

        # Save the uploaded file temporarily
        source_path = temp_upload_dir / filename
        uploaded_file.save(source_path)

        # Reject empty files
        file_size = source_path.stat().st_size

        if file_size == 0:
            return render_template(
                "index.html",
                error="The selected file is empty. Please upload a valid file."
            )

        # Check the configured maximum upload size
        max_size = app.config["MAX_CONTENT_LENGTH"]

        if file_size > max_size:
            return render_template(
                "index.html",
                error="File is too large. The maximum size is 100 MB."
            )

        # Encrypt and segment the file
        manifest_path = encrypt_file(source_path, block_size)

        # Obtain the generated encrypted folder identifier
        folder_name = manifest_path.parent.name

        # Connect to AWS S3
        s3 = get_s3_client()

        # Upload encrypted blocks and manifest only
        for file_path in manifest_path.parent.iterdir():
            if (
                file_path.is_file()
                and (
                    file_path.suffix == ".enc"
                    or file_path.name == "manifest.json"
                )
            ):
                object_key = (
                    f"encrypted_blocks/{folder_name}/{file_path.name}"
                )

                s3.upload_file(
                    str(file_path),
                    BUCKET_NAME,
                    object_key
                )

        return render_template(
            "index.html",
            success="File encrypted and uploaded to AWS S3 successfully!",
            folder_name=folder_name
        )

    except (NoCredentialsError, ClientError, OSError):
        app.logger.exception("File upload failed")

        return render_template(
            "index.html",
            error="Upload failed. Check the server terminal for details."
        )

    except Exception:
        app.logger.exception("Unexpected error during file upload")

        return render_template(
            "index.html",
            error="An unexpected error occurred during upload."
        )

    finally:
        # Remove the temporary plaintext file
        if source_path is not None:
            try:
                source_path.unlink(missing_ok=True)
            except OSError:
                app.logger.exception(
                    "Could not remove temporary plaintext upload"
                )

        # Remove the temporary directory if it is empty
        if temp_upload_dir is not None:
            try:
                temp_upload_dir.rmdir()
            except OSError:
                app.logger.exception(
                    "Could not remove temporary upload directory"
                )


@app.route("/restore", methods=["POST"])
def restore_file():
    folder_name = request.form.get("folder_name", "").strip()

    # Validate the folder identifier
    safe_folder_name = secure_filename(folder_name)

    if not safe_folder_name or safe_folder_name != folder_name:
        return render_template(
            "index.html",
            error="Enter a valid encrypted folder identifier."
        )

    try:
        s3 = get_s3_client()

        prefix = f"encrypted_blocks/{safe_folder_name}/"

        local_folder = CLOUD_DOWNLOAD_DIR / safe_folder_name
        local_folder.mkdir(parents=True, exist_ok=True)

        # List objects from S3
        response = s3.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=prefix
        )

        objects = response.get("Contents", [])

        if not objects:
            return render_template(
                "index.html",
                error="No encrypted files found for that identifier."
            )

        downloaded_manifest = None

        # Download the encrypted blocks and manifest
        for obj in objects:
            key = obj["Key"]
            relative_name = key[len(prefix):]

            # Ignore empty keys and nested paths
            if not relative_name or "/" in relative_name:
                continue

            # Accept only encrypted blocks and the manifest
            if not (
                relative_name.endswith(".enc")
                or relative_name == "manifest.json"
            ):
                continue

            local_path = local_folder / relative_name

            s3.download_file(
                BUCKET_NAME,
                key,
                str(local_path)
            )

            if relative_name == "manifest.json":
                downloaded_manifest = local_path

        if downloaded_manifest is None:
            return render_template(
                "index.html",
                error="The manifest was not found in S3."
            )

        # Decrypt and verify the reconstructed file
        decrypt_file(downloaded_manifest)

        return render_template(
            "index.html",
            success=(
                "Download and decryption completed. "
                "Check the terminal for the SHA-256 integrity result."
            ),
            restored_folder=str(BASE_DIR / "downloads")
        )

    except (NoCredentialsError, ClientError, OSError, ValueError):
        app.logger.exception("File restoration failed")

        return render_template(
            "index.html",
            error="Restoration failed. Check the server terminal for details."
        )

    except Exception:
        app.logger.exception("Unexpected error during restoration")

        return render_template(
            "index.html",
            error=(
                "Restoration failed. The file may be damaged, "
                "or decryption may have failed."
            )
        )


@app.errorhandler(413)
def file_too_large(error):
    return render_template(
        "index.html",
        error="File is too large. The maximum upload size is 100 MB."
    ), 413


if __name__ == "__main__":
    print("Secure Cloud File Storage website starting...")
    print("Open http://127.0.0.1:5000 in your browser.")

    # Debug mode stays disabled
    app.run(debug=False)