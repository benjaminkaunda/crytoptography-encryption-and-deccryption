from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

# Ensure the keys directory exists
os.makedirs("keys", exist_ok=True)

# Generate ECC private key
private_key = ec.generate_private_key(ec.SECP256R1())

# Derive public key from the private key
public_key = private_key.public_key()

# Save private key to file
with open("keys/private_key.pem", "wb") as f:
    f.write(
        # Below function will convert to bytes the private key object
        private_key.private_bytes(  
            encoding=serialization.Encoding.PEM, # output should be in PEM format
            format=serialization.PrivateFormat.PKCS8, # structure of encoded private key
            encryption_algorithm=serialization.NoEncryption() 
        )
    )

# Save public key to file
with open("keys/public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("ECC key pair generated and saved to the 'keys/' folder.")