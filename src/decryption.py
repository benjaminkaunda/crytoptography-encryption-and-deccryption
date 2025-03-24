from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidTag
import os

# Load the private key from file
def load_private_key(file_path):
    with open(file_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key

# Decrypt the message using ECIES
def decrypt_ecies(private_key, ephemeral_public_key_pem, iv, ciphertext, tag):
    # Load the ephemeral public key from PEM format
    ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_key_pem.encode())

    # Perform ECDH to derive the shared secret
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # Derive the symmetric key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_secret)

    # Initialize AES-GCM cipher with the derived key and IV
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()

    try:
        # Decrypt the ciphertext
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()  # Return the decrypted message as a string
    except InvalidTag:
        raise ValueError("Decryption failed: The tag is invalid. The data may be tampered or corrupted.")

# Main function to decrypt the message
if __name__ == "__main__":
    # Paths to keys and encrypted data
    private_key_path = "keys/private_key.pem"
    encrypted_data_path = "output/encrypted_data.txt"

    # Load the private key
    private_key = load_private_key(private_key_path)

    # Read the encrypted data from file
    with open(encrypted_data_path, "r") as f:
        lines = f.readlines()
        ephemeral_public_key_pem = "".join(lines[1:5]).strip()  # Extract the ephemeral public key
        iv_hex = lines[6].split(":")[1].strip()  # Extract the IV
        ciphertext_hex = lines[7].split(":")[1].strip()  # Extract the ciphertext
        tag_hex = lines[8].split(":")[1].strip()  # Extract the tag

    # Convert hex strings to bytes
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    tag = bytes.fromhex(tag_hex)

    # Decrypt the message
    try:
        decrypted_message = decrypt_ecies(private_key, ephemeral_public_key_pem, iv, ciphertext, tag)
        print("Decrypted Message:")
        print(decrypted_message)
    except ValueError as e:
        print(e)