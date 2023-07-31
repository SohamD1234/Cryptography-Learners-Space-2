import sys
import hashlib
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

def get_sha256_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        # Read the file in chunks to handle large files efficiently
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.digest()

def get_rsa_keypair_and_sign(file_path, key_size=2048):
    sha256_bytes = get_sha256_hash(file_path)

    # Generate an RSA key pair with the specified key_size
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # Get the public key
    public_key = private_key.public_key()

    # Serialize and save the keys (you can also use them for signing/verification)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("private_key.pem", "wb") as f:
        f.write(private_key_pem)

    with open("public_key.pem", "wb") as f:
        f.write(public_key_pem)

    # Sign the SHA-256 hash using RSA digital signature
    signature = private_key.sign(
        sha256_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Convert the signature to hexadecimal representation
    signature_hex = signature.hex()

    return (public_key, private_key, signature_hex, public_key.public_numbers().n, public_key.public_numbers().e)

if _name_ == "_main_":
    if len(sys.argv) != 2:
        print("Usage: python3 sign.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    try:
        # Generate RSA Key Pair and Sign the SHA-256 hash
        public_key, private_key, signature_hex, N, e = get_rsa_keypair_and_sign(file_path)

        print(f"N: {N}")
        print(f"e: {e}")
        print(f"Signature (Hex): {signature_hex}")
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")