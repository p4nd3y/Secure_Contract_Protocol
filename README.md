# Secure_Contract_Protocol
# 🔐 Secure Digital Contract Exchange Simulator (Python)

This project simulates a secure property contract exchange between three parties — a UK-based legal firm (Hackit & Run LLP), the seller’s solicitor, and the buyer (Mrs. Harvey). The exchange ensures confidentiality, authentication, and legal enforceability using modern cryptographic methods.

## 📌 Project Overview

- This Python script demonstrates how a secure digital contract transaction can be implemented using:
  - **RSA** for key exchange and digital signatures
  - **AES-256** for encrypting contract data
  - **SHA-256** for hashing and integrity
  - **PBKDF2** for deriving secure AES keys from passwords

## 🧑‍⚖️ Scenario

1. **Seller’s solicitor** drafts a contract and sends it to **H&R LLP**.
2. **H&R LLP** encrypts the contract using AES and sends it to **Mrs. Harvey**.
3. **Mrs. Harvey** decrypts the contract, digitally signs it, and sends it back.
4. **H&R LLP** verifies the signature and forwards the verified contract to the seller's solicitor.

This simulation mimics real-world legal requirements like those defined by the **UK Law of Property Act 1989**, **Electronic Communications Act 2000**, and **EU eIDAS regulation**.

---

## 🔧 Technologies Used

| Purpose                  | Algorithm           |
|--------------------------|---------------------|
| Key Generation           | RSA-2048            |
| Data Encryption          | AES-256 (CBC Mode)  |
| Key Derivation           | PBKDF2 + SHA-256    |
| Digital Signature        | RSA + SHA-256       |
| Message Integrity        | SHA-256             |

## ▶️ How to Run

1. **Install dependencies** (if not already installed):

```bash
pip install cryptography

secure_contract_protocol.py
