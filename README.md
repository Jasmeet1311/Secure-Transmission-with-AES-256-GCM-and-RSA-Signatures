# 🔐 Secure Data Transmission for Healthcare Providers

## 📝 Project Overview

This project demonstrates a **secure way to transmit patient data** using:
- **AES-256 encryption in GCM mode** for confidentiality and integrity
- **RSA digital signatures** for authenticity and tamper detection

It simulates how healthcare providers can **securely share sensitive data** (e.g., with insurance companies or researchers).

---

## 📦 Features

- ✅ AES-256 GCM encryption (industry standard)
- ✅ RSA digital signature support
- ✅ User-provided secure key input
- ✅ Input validation to avoid **weak or banned keys**
- ✅ Encryption/Decryption, Signing/Verification
- ✅ Human-readable logs and outputs

---

## 🔐 Why AES-GCM and RSA?

| Feature           | Purpose                                             |
|------------------|------------------------------------------------------|
| **AES-256 GCM**  | Encrypts and protects integrity of data              |
| **RSA Signature**| Verifies sender and ensures data was not modified    |
| **ECB Mode (Old)**| Vulnerable to attacks (replaced in this version)    |

---

## 🛠️ How It Works

### 🔑 Input

- User enters:
  - Patient data (text)
  - A **256-bit AES key** (64 hex characters)

### 🧪 Key Validation Rules

The AES key will be **rejected** if:
- It's not exactly **64 hexadecimal characters**
- It only contains bytes from the first 5 prime numbers (`2, 3, 5, 7, 11`)
- It includes any of the following **banned patterns**:
  - `"jasmeet"`
  - `"12417307"`

---

## 🚀 Steps Performed by Code

1. **User input** for patient data and AES key
2. **Data encryption** using AES-256-GCM
3. **RSA key pair generation**
4. **Digital signing** of ciphertext
5. **Signature verification**
6. **Decryption** of data back to original

---

## 🧪 Sample Run

```bash
Enter the data to be encrypted: Patient name: John Doe, ID: 92847
Enter a 64-character AES-256 key (hex): 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

✅ Encrypted Data: 7df1c00e...
✅ Signature (hex): 3045022...
✅ Signature Verified! Data is authentic.
✅ Decrypted Data: Patient name: John Doe, ID: 92847
