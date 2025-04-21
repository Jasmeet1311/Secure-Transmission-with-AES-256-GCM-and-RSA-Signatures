from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import binascii

# AES-256 key and IV sizes
AES_KEY_SIZE = 32  # 256 bits
AES_IV_SIZE = 12   # Recommended IV size for GCM

# AES Encryption using GCM mode
def encrypt_AES_GCM(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag

# AES Decryption using GCM mode
def decrypt_AES_GCM(ciphertext, tag, key, iv):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# Generate RSA Key Pair
def generate_RSA_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Sign data using RSA
def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify RSA signature
def verify_signature(public_key, data, signature):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Check if key is weak (only uses small primes)
def is_weak_key(key_bytes):
    weak_primes = {2, 3, 5, 7, 11}
    return all(byte in weak_primes for byte in key_bytes)

# Check for banned patterns in the key
def has_banned_patterns(key_hex):
    banned_terms = ['jasmeet', '12417307']
    return any(term in key_hex.lower() for term in banned_terms)

if __name__ == "__main__":
    # Take user input
    user_data = input("Enter the data to be encrypted: ").encode()

    # User-provided AES key
    while True:
        user_key_hex = input("Enter a 64-character AES-256 key (hex): ")
        if len(user_key_hex) != 64:
            print("❌ Key must be exactly 64 hexadecimal characters (256 bits).")
            continue
        if has_banned_patterns(user_key_hex):
            print("❌ Key contains banned pattern (e.g., 'jasmeet' or '12417307'). Please use a different key.")
            continue
        try:
            key = binascii.unhexlify(user_key_hex)
            if is_weak_key(key):
                print("❌ Weak key detected! Only uses bytes from the first 5 primes (2, 3, 5, 7, 11). Try a stronger key.")
                continue
            break
        except binascii.Error:
            print("❌ Invalid hex string. Please enter a valid 64-character hex key.")

    # Generate random IV
    iv = get_random_bytes(AES_IV_SIZE)

    # Encrypt Data
    ciphertext, tag = encrypt_AES_GCM(user_data, key, iv)
    print("Encrypted Data:", ciphertext.hex())

    # Generate RSA Key Pair
    private_key = generate_RSA_key()
    public_key = private_key.public_key()

    # Sign the encrypted data
    signature = sign_data(private_key, ciphertext)
    print("Signature (hex):", signature.hex())

    # Verify Signature
    if verify_signature(public_key, ciphertext, signature):
        print("Signature Verified! Data is authentic.")
    else:
        print("Signature Verification Failed! Data may be altered.")

    # Decrypt Data
    decrypted = decrypt_AES_GCM(ciphertext, tag, key, iv)
    print("Decrypted Data:", decrypted.decode())

# Key example
# 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08