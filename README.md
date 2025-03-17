# Cryptography Playground - Secure & Fun Encryption Algorithms

## Overview
Welcome to the **Cryptography Playground**, a Streamlit-based interactive platform that allows users to experiment with a variety of cryptographic algorithms. From **classical ciphers** (like Caesar, Atbash, and Vigenère) to **modern encryption techniques** (such as AES, RSA, and RC4), this project provides hands-on experience with different cryptographic methods, including hashing and key exchange.

---

## Features
### 🔒 **Classical Cryptography**
- **Caesar Cipher**: Shift characters by a fixed number.
- **Atbash Cipher**: Reverse alphabet mapping.
- **Vigenère Cipher**: Multi-shift encryption using a key.
- **Folding Cipher**: Text interleaving for obfuscation.

### ⚙️ **Modern Cryptography**
- **AES (Advanced Encryption Standard)**: Secure block cipher in CBC mode.
- **RC4**: Stream cipher for fast encryption.
- **RSA**: Asymmetric cryptography for secure key exchange and digital signatures.
- **Diffie-Hellman**: Secure key exchange method.
- **Hashing Functions**: MD5, SHA-256, SHA-512 for data integrity.
- **HMAC**: Message authentication codes for verifying message authenticity.

### 📊 **Comparative Analysis**
- Benchmark performance of **AES vs RC4** over multiple iterations.
- Visualize execution time using Matplotlib charts.

### 🔐 **Real-World Applications**
- **Password Hashing**: Secure password storage using salting and hashing.
- **File Encryption**: Encrypt and decrypt files securely.
- **Digital Signatures**: Generate and verify message signatures using RSA.

---

## Installation
### Requirements
Ensure you have Python installed along with the necessary dependencies:
```sh
pip install streamlit pycryptodome numpy matplotlib
```

### Run the Application
```sh
streamlit run app.py
```

---

## How It Works
### 🔎 Navigation
- The **sidebar menu** allows you to switch between sections.
- Select an encryption method, enter your text, and see the magic happen!

### 🤖 Encryption & Decryption
- For **classical ciphers**, input your text and a key (if needed).
- For **AES and RSA**, provide an encryption key or generate new ones.
- **Hashing functions** output irreversible hashes useful for integrity checks.

### 💡 Security Insights
- Understand **how each algorithm works** and its real-world use cases.
- See **performance comparisons** between different methods.

---

## Screenshots
![Cryptography Playground Screenshot](screenshot.png)

---

## Why Use This?
🔒 **Educational** - Learn how cryptographic techniques function.
🚀 **Fast & Interactive** - No need for manual implementation.
🌐 **Accessible** - Run directly in your browser using Streamlit.
💪 **Hands-on Practice** - Experiment with secure encryption methods.

---

## Contributors
- **Salmane Koraichi** - Developer & Cryptography Enthusiast

---

## License
This project is **open-source** under the MIT License. Feel free to contribute, modify, and share!

Happy Encrypting! 🔐🔑

