# === IMPORTS ===
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from base64 import b64encode
import os

# === KEY GENERATION ===

# Generate an RSA key pair (private + public)
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Secure standard size
        backend=default_backend()
    )
    return private_key, private_key.public_key()

# === DIGITAL SIGNATURE FUNCTIONS ===

# Sign a message using RSA private key
def sign_data(private_key, data):
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# Verify a digital signature using RSA public key
def verify_signature(public_key, data, signature):
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# === AES ENCRYPTION FUNCTIONS ===

# Encrypt plaintext using AES-CBC
def encrypt_data(key, plaintext):
    iv = os.urandom(16)  # Random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Add PKCS7 padding to make it block aligned
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # Prepend IV to ciphertext for use during decryption

# Decrypt AES-CBC encrypted data
def decrypt_data(key, ciphertext):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ct) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# Derive AES key securely from a password using PBKDF2
def derive_aes_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# === SIMULATION START ===

# Generate RSA key pairs for H&R, Solicitor, and Buyer (Mrs. Harvey)
hr_private, hr_public = generate_rsa_key_pair()
solicitor_private, solicitor_public = generate_rsa_key_pair()
harvey_private, harvey_public = generate_rsa_key_pair()

# Step 1: Seller's solicitor sends a contract to H&R
contract_text = contract_text = "Contract for parcel of land. Price: £500,000.".encode('utf-8')

print("Step 1: Seller -> H&R\nOriginal Contract Text:")
print(contract_text.decode())

# Step 2: H&R encrypts contract with AES and sends to Mrs. Harvey
password = "securepassword123"
salt = os.urandom(16)
aes_key = derive_aes_key(password, salt)
encrypted_contract = encrypt_data(aes_key, contract_text)

print("\nStep 2: H&R -> Mrs. Harvey\nEncrypted Contract Preview (Base64):")
print(b64encode(encrypted_contract[:32]).decode())  # Just a preview of ciphertext

# Step 3: Mrs. Harvey decrypts the contract and signs it
decrypted_contract = decrypt_data(aes_key, encrypted_contract)
signature = sign_data(harvey_private, decrypted_contract)

print("\nStep 3: Mrs. Harvey signs the contract.")

# Step 4: H&R verifies the signature and forwards to Seller’s solicitor
is_verified = verify_signature(harvey_public, decrypted_contract, signature)

print("\nStep 4: H&R -> Seller's Solicitor")
print("Decrypted Contract Received at H&R:", decrypted_contract.decode())
print("Signature Verified by H&R:", "Yes" if is_verified else "No")

# === FINAL SUMMARY ===
print("\n--- Summary ---")
print("Encrypted Contract Size:", len(encrypted_contract), "bytes")
print("Digital Signature Size:", len(signature), "bytes")
print("AES Key (Base64):", b64encode(aes_key).decode())
