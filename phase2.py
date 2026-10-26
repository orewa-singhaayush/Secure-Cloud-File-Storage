import os
import json
import base64
import boto3
import hashlib
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Project folders
BASE_DIR = Path(__file__).resolve().parent
KEY_FILE = BASE_DIR / "encryption_key.bin"
ENCRYPTED_DIR = BASE_DIR / "encrypted_blocks"
DOWNLOAD_DIR = BASE_DIR / "downloads"


def get_encryption_key():
    """Load the existing local key or retrieve it from AWS Secrets Manager."""

    if os.getenv("AWS_EXECUTION_ENV"):
        secret_name = "secure-cloud-storage/aes-key"
        region_name = "eu-north-1"

        client = boto3.client(
            "secretsmanager",
            region_name=region_name
        )

        response = client.get_secret_value(
            SecretId=secret_name
        )

        secret_data = json.loads(response["SecretString"])
        key = base64.b64decode(secret_data["aes_key"], validate=True)

        if len(key) != 32:
            raise ValueError("Encryption key must be exactly 32 bytes.")

        return key

    if KEY_FILE.exists():
        key = KEY_FILE.read_bytes()

        if len(key) != 32:
            raise ValueError("Encryption key must be exactly 32 bytes.")

        return key

    key = AESGCM.generate_key(bit_length=256)

    with KEY_FILE.open("xb") as f:
        f.write(key)

    print("New AES-256 encryption key generated.")
    return key


def calculate_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for data in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(data)

    return sha256.hexdigest()


def encrypt_file(file_path, block_size_mb):
    """Split a file into blocks and encrypt each block."""
    file_path = Path(file_path).resolve()

    if not file_path.is_file():
        raise FileNotFoundError("The selected file does not exist.")

    if block_size_mb <= 0:
        raise ValueError("Block size must be greater than zero.")

    block_size = block_size_mb * 1024 * 1024
    key = get_encryption_key()
    aes = AESGCM(key)

    # Create a unique folder for this encrypted file.
    session = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    output_dir = ENCRYPTED_DIR / f"{file_path.stem}_{session}"
    output_dir.mkdir(parents=True)

    blocks = []
    original_hash = calculate_hash(file_path)

    with open(file_path, "rb") as source:
        index = 1

        while True:
            data = source.read(block_size)

            if not data and index > 1:
                break

            # A unique 12-byte nonce for every block.
            nonce = os.urandom(12)

            encrypted_data = aes.encrypt(nonce, data, None)

            block_name = f"block_{index:03d}.enc"
            block_path = output_dir / block_name

            # Store nonce followed by authenticated ciphertext.
            block_path.write_bytes(nonce + encrypted_data)

            blocks.append(block_name)
            print(f"Encrypted: {block_name}")

            index += 1

            if not data:
                break

    manifest = {
        "original_filename": file_path.name,
        "original_sha256": original_hash,
        "block_size_bytes": block_size,
        "blocks": blocks,
    }

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=4))

    print(f"\nTotal blocks created: {len(blocks)}")
    print(f"Encrypted files saved in: {output_dir}")

    return manifest_path


def decrypt_file(manifest_path):
    """Decrypt blocks, reconstruct the file, and verify its hash."""
    manifest_path = Path(manifest_path).resolve()
    output_dir = manifest_path.parent

    manifest = json.loads(manifest_path.read_text())
    key = get_encryption_key()
    aes = AESGCM(key)

    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

    # Avoid overwriting existing reconstructed files.
    session = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    restored_dir = DOWNLOAD_DIR / session
    restored_dir.mkdir(parents=True)

    output_file = restored_dir / manifest["original_filename"]

    with open(output_file, "wb") as destination:
        for block_name in manifest["blocks"]:
            encrypted_data = (output_dir / block_name).read_bytes()

            if len(encrypted_data) < 28:
                raise ValueError(f"Invalid encrypted block: {block_name}")

            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]

            # Decryption also verifies AES-GCM authentication.
            decrypted_data = aes.decrypt(nonce, ciphertext, None)
            destination.write(decrypted_data)

            print(f"Decrypted: {block_name}")

    restored_hash = calculate_hash(output_file)
    original_hash = manifest["original_sha256"]

    print(f"\nRestored file: {output_file}")
    print(f"Original SHA-256:   {original_hash}")
    print(f"Restored SHA-256:   {restored_hash}")

    if restored_hash == original_hash:
        print("\nSUCCESS: Original file reconstructed correctly!")
    else:
        print("\nERROR: File integrity verification failed!")


if __name__ == "__main__":
    print("=== SECURE CLOUD FILE STORAGE ===")
    print("1. Split and encrypt a file")
    print("2. Decrypt and reconstruct a file")

    choice = input("\nEnter your choice (1 or 2): ").strip()

    try:
        if choice == "1":
            file_path = input("Enter the file path: ").strip().strip('"')
            size = int(input("Enter block size in MB (e.g., 1): "))

            manifest = encrypt_file(file_path, size)

            print("\nStarting local decryption test...")
            decrypt_file(manifest)

        elif choice == "2":
            manifest_path = input(
                "Enter the path to manifest.json: "
            ).strip().strip('"')

            decrypt_file(manifest_path)

        else:
            print("Invalid choice. Please enter 1 or 2.")

    except Exception as error:
        print(f"\nOperation failed: {error}")