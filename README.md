# **CryptoVault: Secure File Encryption Tool**  

CryptoVault is a powerful and user-friendly Python-based tool designed to securely encrypt and decrypt files using modern cryptographic algorithms. By combining the efficiency of **AES-256-CBC** for symmetric encryption and the security of **RSA-2048** for asymmetric key wrapping, CryptoVault ensures that your sensitive data remains protected from unauthorized access. Whether you're securing personal files, sharing confidential documents, or learning about encryption, CryptoVault provides a robust solution.

---

## **Features**  

### **1. Hybrid Encryption System**
- **AES-256-CBC Encryption:** Encrypts file data using a randomly generated 256-bit AES key, ensuring fast and secure encryption for large files.
- **RSA-2048 Key Wrapping:** Encrypts the AES key using RSA, providing a secure method for key exchange and storage.
- **Random Initialization Vector (IV):** Each encryption operation uses a unique IV, ensuring semantic security and preventing pattern analysis.

### **2. Command-Line Interface (CLI)**
- Simple and intuitive commands for generating keys, encrypting files, and decrypting files.
- Cross-platform compatibility: Works on Windows, macOS, and Linux.

### **3. Secure Key Management**
- Generates RSA public and private keys for secure encryption and decryption.
- Private keys are stored locally and should be protected with strong access controls.

### **4. Extensible and Open Source**
- Built with Python and the PyCryptodome library, making it easy to extend and customize.
- Open-source under the MIT License, allowing for community contributions and improvements.

---

## **Use Cases**  

- **Secure File Storage:** Encrypt sensitive files before storing them on cloud services or external drives.
- **Confidential File Sharing:** Share encrypted files securely, knowing that only the intended recipient can decrypt them.
- **Educational Tool:** Learn about hybrid encryption systems, symmetric and asymmetric cryptography, and secure key management.
- **Data Protection:** Protect personal or business data from unauthorized access or breaches.

---

## **Installation**  

### **Prerequisites**
- Python 3.x installed on your system.
- PyCryptodome library for cryptographic operations.

### **Steps**
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/CryptoVault.git
   cd CryptoVault
   ```

2. Install the required dependencies:
   ```bash
   pip install pycryptodome
   ```

3. Run the tool using the provided CLI commands.

---

## **Usage**  

### **1. Generate RSA Keys**
Generate a pair of RSA public and private keys:
```bash
python crypto_tool.py generate_keys
```
This will create two files:
- `private_key.pem`: Your private key (keep this secure!).
- `public_key.pem`: Your public key (share this with others).

### **2. Encrypt a File**
Encrypt a file using the public key:
```bash
python crypto_tool.py encrypt input.txt encrypted.enc
```
- `input.txt`: The file you want to encrypt.
- `encrypted.enc`: The output encrypted file.

### **3. Decrypt a File**
Decrypt a file using the private key:
```bash
python crypto_tool.py decrypt encrypted.enc decrypted.txt
```
- `encrypted.enc`: The encrypted file.
- `decrypted.txt`: The output decrypted file.

---

## **How It Works**  

1. **Encryption Process:**
   - A random AES-256 key is generated.
   - The file data is encrypted using AES-256-CBC with a random IV.
   - The AES key is encrypted using RSA-2048 with the recipient's public key.
   - The encrypted AES key, IV, and encrypted data are combined into a single output file.

2. **Decryption Process:**
   - The encrypted file is split into the encrypted AES key, IV, and encrypted data.
   - The AES key is decrypted using the recipient's private key.
   - The file data is decrypted using AES-256-CBC with the decrypted AES key and IV.

---

## **Contributing**  

We welcome contributions to improve CryptoVault! Here’s how you can help:
1. **Report Issues:** Found a bug or have a feature request? Open an issue on GitHub.
2. **Submit Pull Requests:** Have an improvement or fix? Submit a pull request with a detailed description of your changes.
3. **Spread the Word:** Share this project with others who might find it useful.

---

## **Acknowledgements**  

- Built using the [PyCryptodome](https://pycryptodome.readthedocs.io/) library for cryptographic operations.
- Inspired by the need for simple, secure, and open-source encryption tools.

---

## **Support**  

If you find this project useful, consider giving it a ⭐️ on GitHub! For questions or support, feel free to open an issue or reach out to the maintainers.

---
