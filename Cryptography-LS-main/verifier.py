import sys
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

def get_sha256_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        # Read the file in chunks to handle large files efficiently
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.digest()

def verify_signature(file_path, N, e, signature_hex):
    sha256_bytes = get_sha256_hash(file_path)

    # Convert the signature back to bytes from hexadecimal
    signature = bytes.fromhex(signature_hex)

    # Load the public key using (N, e)
    public_numbers = rsa.RSAPublicNumbers(e, N)
    public_key = public_numbers.public_key()

    try:
        # Verify the signature
        public_key.verify(
            signature,
            sha256_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return "accept"  # Signature is valid
    except InvalidSignature:
        return "reject"  # Signature is invalid

if _name_ == "_main_":
    if len(sys.argv) != 5:
        print("Usage: python3 verifier.py <file_path> <N> <e> <signature_hex>")
        sys.exit(1)

    file_path = sys.argv[1]
    N = int(sys.argv[2])
    e = int(sys.argv[3])
    signature_hex = sys.argv[4]

    try:
        result = verify_signature(file_path, N, e, signature_hex)
        print(f"Verification Result: {result}")
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")