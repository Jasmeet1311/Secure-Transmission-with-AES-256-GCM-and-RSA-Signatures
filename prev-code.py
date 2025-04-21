from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

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

# Generate ECDSA Key Pair
def generate_EC_key():
    return ec.generate_private_key(ec.SECP256R1())

# Sign data using ECDSA
def sign_data(private_key, data):
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature

# Verify ECDSA signature
def verify_signature(public_key, data, signature):
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False

if __name__ == "_main_":
    # Take user input
    user_data = input("Enter the data to be encrypted: ").encode()

    # Generate AES key and IV
    key = get_random_bytes(AES_KEY_SIZE)
    iv = get_random_bytes(AES_IV_SIZE)

    # Encrypt Data
    ciphertext, tag = encrypt_AES_GCM(user_data, key, iv)
    print("Encrypted Data:", ciphertext.hex())

    # Generate ECDSA Key Pair
    private_key = generate_EC_key()
    public_key = private_key.public_key()

    # Sign the encrypted data
    signature = sign_data(private_key, ciphertext)
    print("Signature:", signature.hex())

    # Verify Signature
    if verify_signature(public_key, ciphertext, signature):
        print("Signature Verified! Data is authentic.")
    else:
        print("Signature Verification Failed! Data may be altered.")

    # Decrypt Data
    decrypted = decrypt_AES_GCM(ciphertext, tag, key, iv)
    print("Decrypted Data:", decrypted.decode())