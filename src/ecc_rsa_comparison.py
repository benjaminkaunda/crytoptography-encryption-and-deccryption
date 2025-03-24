# src/ecc_rsa_comparison.py
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes
from utils import encrypt_ecies  # Import the function
from timeit import timeit

# Measure ECC key generation time
ecc_key_gen_time = timeit(lambda: ec.generate_private_key(ec.SECP256R1()), number=1000)

# Measure RSA key generation time
rsa_key_gen_time = timeit(lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048), number=1000)

# Measure ECC encryption time
message = b"Hello, this is a secret message!"
ecc_private_key = ec.generate_private_key(ec.SECP256R1())
ecc_public_key = ecc_private_key.public_key()
ecc_encrypt_time = timeit(lambda: encrypt_ecies(ecc_public_key, message), number=1000)

# Measure RSA encryption time
rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_public_key = rsa_private_key.public_key()
rsa_encrypt_time = timeit(
    lambda: rsa_public_key.encrypt(message, OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)),
    number=1000
)

# Save results to file
with open("output/performance_results.txt", "w") as f:
    f.write("Performance Comparison Results:\n")
    f.write(f"ECC Key Generation Time (1000 iterations): {ecc_key_gen_time:.6f} seconds\n")
    f.write(f"RSA Key Generation Time (1000 iterations): {rsa_key_gen_time:.6f} seconds\n")
    f.write(f"ECC Encryption Time (1000 iterations): {ecc_encrypt_time:.6f} seconds\n")
    f.write(f"RSA Encryption Time (1000 iterations): {rsa_encrypt_time:.6f} seconds\n")

print("Performance comparison results saved to 'output/performance_results.txt'.")