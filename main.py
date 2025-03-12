import os
import json
import base64

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

# Define the API server
app = FastAPI()

# Path to the private key
PRIVATE_KEY_PATH = "/mnt/keystore/private_key.pem"
PUBLIC_KEY_PATH = "/mnt/keystore/public_key.pem"
PROOF_FILE_PATH = "/mnt/keystore/proof.json"


class SignRequest(BaseModel):
    hash: str


def load_private_key():
    if not os.path.exists(PRIVATE_KEY_PATH):
        raise FileNotFoundError("Private key file not found.")

    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None  # Adjust if the key is password-protected
        )
    return private_key


def load_public_key():
    if not os.path.exists(PUBLIC_KEY_PATH):
        raise FileNotFoundError("Public key file not found.")

    with open(PUBLIC_KEY_PATH, "rb") as key_file:
        public_key = key_file.read()

    return public_key


def load_proof_data():
    if not os.path.exists(PROOF_FILE_PATH):
        raise FileNotFoundError("Proof file not found.")

    with open(PUBLIC_KEY_PATH, "rb") as proof_file:
        proof_data = json.loads(proof_file.read())

    return proof_data


@app.post("/sign")
def sign_data(request: SignRequest):
    try:
        # Validate input hash
        if request.hash.lower() != request.hash:
            raise ValueError("SHA-256 hash must be in lowercase.")

        if len(request.hash) != 64 or not all(c in "0123456789abcdef" for c in request.hash):
            raise ValueError("Invalid SHA-256 hash format.")

        # Convert hash hex to bytes
        hash_bytes = bytes.fromhex(request.hash)

        # Load the private key
        private_key = load_private_key()

        # Load the public key
        public_key = load_public_key()

        # Load proof data
        proof_data = load_proof_data()

        # Sign the hash
        signature = private_key.sign(
            hash_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Return the base64-encoded signature
        return {
            "hash": request.hash,
            "signature": base64.b64encode(signature).decode(),
            "pubKey": public_key,
            "launchProof": proof_data
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
