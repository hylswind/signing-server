import os
import base64

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

# Define the API server
app = FastAPI()

# Path to the private key
PRIVATE_KEY_PATH = "/mnt/keystore/private_key.pem"


class SignRequest(BaseModel):
    hash: str


def load_private_key():
    """Load the RSA 2048 private key from the file."""
    if not os.path.exists(PRIVATE_KEY_PATH):
        raise FileNotFoundError("Private key file not found.")

    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None  # Adjust if the key is password-protected
        )
    return private_key


@app.post("/signing")
def sign_data(request: SignRequest):
    try:
        # Validate input hash
        if len(request.hash) != 64 or not all(c in "0123456789abcdef" for c in request.hash.lower()):
            raise ValueError("Invalid SHA-256 hash format.")

        # Convert hash hex to bytes
        hash_bytes = bytes.fromhex(request.hash.lower())

        # Load the private key
        private_key = load_private_key()

        # Sign the hash
        signature = private_key.sign(
            hash_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Return the base64-encoded signature
        return {"hash": request.hash.lower(), "signature": base64.b64encode(signature).decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
