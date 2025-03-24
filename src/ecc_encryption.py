# src/ecc_encryption.py
from cryptography.hazmat.primitives import serialization
from utils import encrypt_ecies  # Import the function
import os

# Load the public key from file
with open("keys/public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Example usage
message = b"Hello, this is a secret message!"
encrypted_data = encrypt_ecies(public_key, message)

# Save encrypted data to file
with open("output/encrypted_data.txt", "w") as f:
    f.write(f"Ephemeral Public Key:\n{encrypted_data[0].decode()}\n")
    f.write(f"IV: {encrypted_data[1].hex()}\n")
    f.write(f"Ciphertext: {encrypted_data[2].hex()}\n")
    f.write(f"Tag: {encrypted_data[3].hex()}\n")

print("Message encrypted and saved to 'output/encrypted_data.txt'.")