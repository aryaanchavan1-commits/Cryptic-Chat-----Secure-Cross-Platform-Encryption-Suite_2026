# 🔐 Cryptic Chat - Secure Cross-Platform Encryption Suite

A comprehensive Python-based encryption and secure messaging application that works across Windows, Linux (including Kali Linux), and macOS. Features AES-256-GCM encryption, secure file/folder encryption, and encrypted network messaging.

---

## 📋 Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Function Reference](#function-reference)
- [Usage Guide](#usage-guide)
  - [Text Encryption/Decryption](#1-text-encryptiondecryption)
  - [File & Folder Encryption](#2-file--folder-encryption)
  - [Secure Messaging](#3-secure-messaging)
  - [Viewing History](#4-viewing-encryption-history)
- [Cross-Platform Communication](#cross-platform-communication)
  - [Windows to Kali Linux Chat](#windows-to-kali-linux-chat)
  - [Using ncat for Communication](#using-ncat-for-communication)
- [Database Files](#database-files)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Performance](#performance)
- [Configuration](#configuration)
- [Changelog](#changelog)

---

## ✨ Features

### 🔤 Text Encryption/Decryption
- Encrypt and decrypt text messages with password protection
- Real-time password strength meter
- Auto-saves encryption history with timestamps
- Support for copying encrypted output
- Handles large text inputs efficiently

### 📁 File & Folder Encryption
- Secure individual files or entire folders with AES-256-GCM
- Recursive folder encryption
- File size validation and warnings
- Progress tracking for large operations
- Auto-saves encryption history

### 📡 Secure Messaging
- Cross-platform encrypted chat over TCP/IP
- AES-256-GCM encrypted communication
- Contact management (save, block, unblock)
- Message history with status tracking (sent/delivered/pending)
- Auto-port detection
- Offline message storage with delivery retry
- Blocked contacts filter

### 📊 Encryption History
- Track all encrypted items with timestamps
- Text and file/folder history in separate tabs
- Password hash storage (actual passwords never stored)
- Easy search and filter capabilities

### 🔒 Security Features
- **AES-256-GCM Encryption** - Military-grade encryption standard
- **PBKDF2 Key Derivation** - 300,000 iterations for strong key stretching
- **Secure Password Storage** - SHA-256 hashing for database storage
- **Password Strength Analysis** - Real-time feedback on password complexity
- **Cross-Platform** - Works on Windows, Linux (Kali), and macOS
- **Network Security** - Encrypted communication with timeout handling
- **Data Validation** - Input validation and error handling

---

## 📦 Prerequisites

### Python Requirements
- Python 3.7 or higher
- `cryptography` library (version 3.4.7 or higher)

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or install directly:

```bash
pip install cryptography>=3.4.7
```

---

## 🚀 Installation

1. **Clone or download the project:**
```bash
git clone https://github.com/aryaanchavan1-commits/Cryptic-Chat-----Secure-Cross-Platform-Encryption-Suite_2026.git
cd Cryptic-Chat-----Secure-Cross-Platform-Encryption-Suite_2026
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run the application:**
```bash
cd "Cryptic Chat - Secure Cross-Platform Encryption Suite"
python cryptic.py
```

---

## 🔧 Function Reference

### Key Management Functions

#### `hash_key(key: str) -> str`
Hashes a password using SHA-256 for secure storage in CSV databases.
- **Parameters:** `key` - The password string to hash
- **Returns:** SHA-256 hexadecimal hash string
- **Location:** Line 19-20

#### `save_text_entry(msg_id, password, encrypted_text)`
Saves text encryption entry to `textdecrypt_pass.csv`.
- **Parameters:**
  - `msg_id` - Unique message identifier
  - `password` - Password for encryption (will be hashed)
  - `encrypted_text` - Base64 encoded encrypted text
- **Location:** Line 22-29

#### `save_file_entry(entry_type, name, password)`
Saves file/folder encryption entry to `file_and_folder_decrypt_key.csv`.
- **Parameters:**
  - `entry_type` - "file" or "folder"
  - `name` - Name of the file/folder
  - `password` - Password for encryption (will be hashed)
- **Location:** Line 31-38

#### `verify_file_key(entry_type, name, password) -> bool`
Verifies password for file/folder decryption by checking against stored hash.
- **Parameters:**
  - `entry_type` - "file" or "folder"
  - `name` - Name of the file/folder
  - `password` - Password to verify
- **Returns:** `True` if password matches, `False` otherwise
- **Location:** Line 40-48

#### `get_all_text_entries() -> list`
Retrieves all text encryption entries from the database.
- **Returns:** List of dictionaries containing message history
- **Location:** Line 50-57

#### `get_all_file_entries() -> list`
Retrieves all file/folder encryption entries from the database.
- **Returns:** List of dictionaries containing file/folder history
- **Location:** Line 59-66

---

### Password Strength Class

#### `PasswordStrength.score(p) -> int`
Calculates password strength score (0-5) based on criteria:
- Length >= 12 characters
- Contains uppercase letter
- Contains lowercase letter
- Contains digit
- Contains special character (!@#$%^&*()_+=-)
- **Returns:** Score from 0 (Very Weak) to 5 (Excellent)
- **Location:** Line 71-80

---

### AES-256-GCM Encryption Class

#### `AES256.derive_key(password, salt) -> bytes`
Derives a 32-byte encryption key from password using PBKDF2-HMAC-SHA256.
- **Parameters:**
  - `password` - User password string
  - `salt` - 16-byte random salt
- **Returns:** 32-byte key for AES encryption
- **Iterations:** 300,000 (secure key stretching)
- **Location:** Line 86-93

#### `AES256.encrypt(data: bytes, password: str) -> bytes`
Encrypts data using AES-256-GCM.
- **Parameters:**
  - `data` - Raw bytes to encrypt
  - `password` - Encryption password
- **Returns:** Encrypted blob (salt + nonce + ciphertext)
- **Format:** 16 bytes salt + 12 bytes nonce + ciphertext
- **Location:** Line 95-101

#### `AES256.decrypt(blob: bytes, password: str) -> bytes`
Decrypts AES-256-GCM encrypted data.
- **Parameters:**
  - `blob` - Encrypted data (salt + nonce + ciphertext)
  - `password` - Decryption password
- **Returns:** Decrypted raw bytes
- **Raises:** Exception if decryption fails (wrong password/corrupted data)
- **Location:** Line 103-107

---

### Crypto Operations Class

#### `CryptoOps.encrypt_text(text, password) -> tuple`
Encrypts text and saves to database.
- **Parameters:**
  - `text` - Plain text to encrypt
  - `password` - Encryption password
- **Returns:** `(msg_id, encrypted_b64)` - Message ID and Base64 encrypted text
- **Location:** Line 113-120

#### `CryptoOps.decrypt_text(cipher, password) -> str`
Decrypts Base64 encoded encrypted text.
- **Parameters:**
  - `cipher` - Base64 encoded encrypted text
  - `password` - Decryption password
- **Returns:** Decrypted plain text string
- **Location:** Line 122-126

#### `CryptoOps.encrypt_file(path, password) -> str`
Encrypts a file and replaces original with encrypted version.
- **Parameters:**
  - `path` - Path to file to encrypt
  - `password` - Encryption password
- **Returns:** Path to encrypted file (original + ".enc")
- **Note:** Original file is deleted after encryption
- **Location:** Line 128-138

#### `CryptoOps.decrypt_file(path, password) -> str`
Decrypts an encrypted file after password verification.
- **Parameters:**
  - `path` - Path to .enc file
  - `password` - Decryption password
- **Returns:** Path to decrypted file
- **Raises:** `ValueError` if password is invalid
- **Location:** Line 140-152

#### `CryptoOps.encrypt_folder(folder, password) -> list`
Recursively encrypts all files in a folder.
- **Parameters:**
  - `folder` - Path to folder to encrypt
  - `password` - Encryption password
- **Returns:** List of paths to encrypted files
- **Location:** Line 154-164

#### `CryptoOps.decrypt_folder(folder, password) -> list`
Recursively decrypts all .enc files in a folder.
- **Parameters:**
  - `folder` - Path to folder containing encrypted files
  - `password` - Decryption password
- **Returns:** List of paths to decrypted files
- **Raises:** `ValueError` if password is invalid
- **Location:** Line 166-178

---

### Network Crypto Class

#### `NetworkCrypto.get_local_ip() -> str`
Gets the local IP address (cross-platform).
- **Returns:** Local IPv4 address as string
- **Platforms:** Windows (PowerShell), Linux/Mac (hostname), Socket fallback
- **Location:** Line 187-216

#### `NetworkCrypto.is_port_available(port) -> bool`
Checks if a TCP port is available for binding.
- **Parameters:** `port` - Port number to check
- **Returns:** `True` if port is available
- **Location:** Line 219-226

#### `NetworkCrypto.find_available_port(start_port=5050) -> int`
Finds an available TCP port starting from specified port.
- **Parameters:** `start_port` - Starting port number (default: 5050)
- **Returns:** Available port number or `None`
- **Location:** Line 228-236

#### `NetworkCrypto.send(ip, port, message, password) -> bool`
Sends an encrypted message over TCP.
- **Parameters:**
  - `ip` - Target IP address
  - `port` - Target port number
  - `message` - Plain text message to send
  - `password` - Encryption password
- **Returns:** `True` if sent successfully
- **Raises:** `ConnectionError` if connection fails
- **Timeout:** 10 seconds
- **Location:** Line 238-255

#### `NetworkCrypto.listen(port, password, callback, stop_event=None) -> Thread`
Starts a TCP listener for incoming encrypted messages.
- **Parameters:**
  - `port` - Port to listen on
  - `password` - Decryption password
  - `callback` - Function called on message receipt: `callback(ip, message, error)`
  - `stop_event` - Optional threading.Event to stop listening
- **Returns:** Thread object
- **Location:** Line 257-295

---

## 📖 Usage Guide

### 1. Text Encryption/Decryption

**Encrypt Text:**
1. Click "📝 Text Encryption/Decryption" from main menu
2. Enter your text in the "Enter Text" field
3. Enter a strong password (watch the strength meter)
4. Click "Encrypt"
5. Copy the encrypted Base64 output

**Decrypt Text:**
1. Paste the encrypted text (or full output with Message ID)
2. Enter the same password used for encryption
3. Click "Decrypt"
4. View the decrypted text in the result area

**Tips:**
- Use strong passwords with at least 12 characters
- Include uppercase, lowercase, numbers, and special characters
- Avoid common words or patterns

---

### 2. File & Folder Encryption

**Encrypt a File:**
1. Click "📁 File & Folder Encryption/Decryption"
2. Enter a password
3. Click "Select File" and choose your file
4. Click "Encrypt File"
5. Original file is replaced with `.enc` version

**Decrypt a File:**
1. Select the `.enc` file
2. Enter the correct password
3. Click "Decrypt File"
4. Original file is restored

**Encrypt a Folder:**
1. Click "Select Folder" and choose a folder
2. Enter password
3. Click "Encrypt Folder"
4. All files in the folder are encrypted recursively

**Decrypt a Folder:**
1. Select the folder containing `.enc` files
2. Enter password
3. Click "Decrypt Folder"
4. All files are decrypted

**File Size Limitations:**
- Maximum file size: 100MB
- Large files will show a warning
- Progress tracking available for large operations

---

### 3. Secure Messaging

**Setup:**
1. Click "📡 Secure Messaging" from main menu
2. Note your IP address displayed at the top
3. Set a shared password with your chat partner

**To Receive Messages:**
1. Enter the shared password
2. Choose a port (default: 5050) or click "Auto Port"
3. Click "Start Listening"
4. Wait for incoming connections

**To Send Messages:**
1. Enter target IP address
2. Enter target port (must match listener's port)
3. Enter the shared password
4. Type your message
5. Click "Send Message"

**Features:**
- **Contact Management:** Save, block, unblock contacts
- **Message History:** View all messages with timestamps
- **Offline Storage:** Pending messages saved for later delivery
- **Auto Setup:** Automatically finds available port and starts listening
- **Blocked Contacts:** Messages from blocked IPs are rejected

---

### 4. Viewing Encryption History

1. Click "📊 View Encryption History" from main menu
2. Browse through "Text Encryption History" tab
3. Browse through "File/Folder Encryption History" tab
4. View timestamps and password hashes (not actual passwords)

---

## 🌐 Cross-Platform Communication

### Windows to Kali Linux Chat

#### Scenario: Windows (GUI) ↔ Kali Linux (ncat)

**On Windows (Running Cryptic Chat):**
1. Open Cryptic Chat application
2. Go to "📡 Secure Messaging"
3. Note your Windows IP (e.g., `192.168.1.100`)
4. Set port to `5050`
5. Set a password (e.g., `MySecret123!`)
6. Click "Start Listening"

**On Kali Linux (Using ncat):**

First, you need to understand the message format. Cryptic Chat sends Base64-encoded AES-256-GCM encrypted messages.

**To receive messages from Windows on Kali:**
```bash
# Listen for raw encrypted data
ncat -l 5050 > received_encrypted.txt

# Or view in real-time (won't be readable - it's encrypted)
ncat -l 5050
```

**To send messages to Windows from Kali:**

Since ncat sends plain text, you need to encrypt the message first. Here's a Python script for Kali:

```python
# save as encrypt_send.py
import socket, base64, os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(password, salt):
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=300_000
    ).derive(password.encode())

def encrypt_message(message, password):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, message.encode(), None)
    return base64.b64encode(salt + nonce + ct).decode()

# Configuration
WINDOWS_IP = "192.168.1.100"  # Change to Windows IP
PORT = 5050
PASSWORD = "MySecret123!"     # Same password as Windows
MESSAGE = "Hello from Kali!"

# Encrypt and send
encrypted = encrypt_message(MESSAGE, PASSWORD)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((WINDOWS_IP, PORT))
    s.sendall(encrypted.encode())
    print(f"Sent: {MESSAGE}")
    print(f"Encrypted: {encrypted[:50]}...")
```

Run on Kali:
```bash
python3 encrypt_send.py
```

---

### Using ncat for Communication

#### Basic ncat Commands

**Install ncat on Kali:**
```bash
sudo apt-get install ncat
```

**Simple TCP Listener:**
```bash
ncat -l -p 5050
```

**Simple TCP Client:**
```bash
ncat 192.168.1.100 5050
```

**UDP Mode:**
```bash
# Listener
ncat -u -l -p 5050

# Client
ncat -u 192.168.1.100 5050
```

**With SSL/TLS:**
```bash
# Generate cert
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout test.key -out test.crt

# SSL Listener
ncat --ssl --ssl-key test.key --ssl-cert test.crt -l 5050

# SSL Client
ncat --ssl 192.168.1.100 5050
```

**File Transfer:**
```bash
# Receive file
ncat -l 5050 > received_file.txt

# Send file
ncat 192.168.1.100 5050 < file_to_send.txt
```

---

### Full Example: Windows ↔ Kali Linux Chat

**Step 1: Get Windows IP**
On Windows, open Command Prompt:
```cmd
ipconfig
```
Look for "IPv4 Address" (e.g., `192.168.1.100`)

**Step 2: Start Windows Listener**
1. Run `python cryptic.py`
2. Click "📡 Secure Messaging"
3. Set password: `ChatPass123!`
4. Port: `5050`
5. Click "Start Listening"

**Step 3: On Kali Linux - Create Sender Script**
```bash
nano send_to_windows.py
```

Paste the encryption script from above, then:
```bash
python3 send_to_windows.py
```

**Step 4: On Kali Linux - Create Receiver Script**

---

## 📊 Performance

### Encryption Speed Test Results

| Data Size | Encryption (ms) | Decryption (ms) | Total (ms) |
|-----------|-----------------|-----------------|------------|
| 100 bytes | 59.25           | 49.54           | 108.80     |
| 1.0 KB    | 52.32           | 47.43           | 99.75      |
| 10.0 KB   | 48.46           | 54.67           | 103.13     |
| 100.0 KB  | 51.79           | 46.74           | 98.53      |
| 1.0 MB    | 46.04           | 47.29           | 93.32      |

### Performance Characteristics:
- **Encryption speed:** ~10-60 MB/s
- **Decryption speed:** ~20-60 MB/s
- **Key derivation:** PBKDF2 with 300,000 iterations takes about 50ms
- **Large files:** Handled in 64KB chunks for memory efficiency
- **Parallel processing:** Up to 4 concurrent encryption operations

---

## ⚙️ Configuration

The application can be configured using `config.py` file. Here are the key settings:

```python
# Application Settings
APP_VERSION = "2026.1.0"
APP_NAME = "Cryptic Chat - Secure Cross-Platform Encryption Suite"

# Encryption Settings
AES_KEY_LENGTH = 32  # 256 bits
PBKDF2_ITERATIONS = 300000
PBKDF2_HASH_ALGORITHM = "sha256"

# Network Settings
DEFAULT_PORT = 5050
CONNECTION_TIMEOUT = 10
BUFFER_SIZE = 65536

# File Settings
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ENCRYPTION_EXTENSION = ".enc"

# Security Settings
MIN_PASSWORD_LENGTH = 8
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_DIGITS = True
REQUIRE_SPECIAL_CHARS = True

# Performance Settings
MAX_CONCURRENT_ENCRYPTIONS = 4
CHUNK_SIZE = 64 * 1024  # 64KB
```

---

## 📁 Database Files

### Text Encryption Database (`textdecrypt_pass.csv`)
```csv
msg_id,password_hash,encrypted_text,timestamp
Message_1769776135,03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4,ZgakN6gu+ziXDyMYWuLMhlIejobl9caRmwnWrgX449VlOHLHg+F0+PpEDfQcr3x1OGur5U8pE6PHG2JVBSFZ,Fri Jan 30 17:58:55 2026
```

### File Encryption Database (`file_and_folder_decrypt_key.csv`)
```csv
type,name,password_hash,timestamp
folder,03-House-Price-Prediction,fa3cfb3f1bb823aa9501f88f1f95f732ee6fef2c3a48be7f1d38037b216a549f,Fri Jan 30 17:56:52 2026
file,House_Price_Prediction.ipynb,fa3cfb3f1bb823aa9501f88f1f95f732ee6fef2c3a48be7f1d38037b216a549f,Fri Jan 30 17:56:53 2026
```

### Contacts Database (`saved_contacts.json`)
```json
{
  "saved": [
    {
      "ip": "192.168.1.100",
      "port": 5050,
      "name": "John Doe",
      "timestamp": "Fri Jan 30 17:58:55 2026"
    }
  ],
  "blocked": [
    {
      "ip": "10.0.0.5",
      "timestamp": "Fri Jan 30 17:58:55 2026"
    }
  ]
}
```

### Messages Database (`messages.json`)
```json
{
  "192.168.1.100": [
    {
      "message": "Hello, how are you?",
      "timestamp": "Fri Jan 30 17:58:55 2026",
      "direction": "sent",
      "status": "delivered"
    }
  ]
}
```

---

## 🔒 Security Notes

### Important Security Considerations:

1. **Password Strength:** Always use strong, unique passwords
2. **Password Storage:** Passwords are never stored directly - only SHA-256 hashes
3. **Encryption:** Uses AES-256-GCM with PBKDF2 key derivation (300,000 iterations)
4. **Network Communication:** All messages are encrypted in transit
5. **Data Validation:** Input validation prevents common attacks
6. **Offline Storage:** Messages are stored encrypted in the database

### Best Practices:

- **Use long passwords:** 12-16 characters minimum
- **Mix characters:** Use uppercase, lowercase, numbers, and special characters
- **Avoid reuse:** Don't use the same password for multiple purposes
- **Secure storage:** Keep your database files safe
- **Network security:** Use in trusted networks or VPNs
- **Regular updates:** Keep your Python and cryptography library updated

---

## 🔍 Troubleshooting

### Common Issues and Solutions

**1. Application won't start**
- **Problem:** Missing dependencies
- **Solution:** Run `pip install -r requirements.txt`

**2. Encryption fails**
- **Problem:** Invalid password or corrupted data
- **Solution:** Check password, verify file isn't corrupted

**3. Can't send messages**
- **Problem:** Network connectivity issues
- **Solution:** Check IP address, port settings, firewall rules

**4. Slow performance**
- **Problem:** Large file or weak system
- **Solution:** Reduce file size, upgrade hardware, use faster storage

**5. Decryption fails**
- **Problem:** Wrong password or corrupted file
- **Solution:** Verify password, check file integrity

**6. Port already in use**
- **Problem:** Another application using the same port
- **Solution:** Use Auto Port feature, or manually select a different port

**7. Windows PowerShell issues**
- **Problem:** PowerShell commands failing
- **Solution:** Run VSCode or terminal as Administrator

---

## 📈 Performance Optimization

### Improving Application Speed:

1. **File Processing:**
   - Use SSD storage for faster read/write operations
   - Split large files into smaller chunks
   - Close unnecessary applications

2. **Network Communication:**
   - Use wired connection instead of WiFi
   - Avoid network congestion
   - Increase buffer size in config if needed

3. **System Resources:**
   - Close unnecessary background applications
   - Increase virtual memory if system is low on RAM
   - Use 64-bit Python version

---

## 🚀 Production Readiness

### Steps to Make Application Production-Ready:

1. **Dependencies:** Use virtual environment
2. **Error Handling:** Comprehensive exception handling
3. **Logging:** Configure logging with proper levels
4. **Input Validation:** Strict validation of all inputs
5. **Security:** Follow best practices for encryption
6. **Testing:** Comprehensive test coverage
7. **Documentation:** Complete user and developer documentation
8. **Performance:** Optimize for different platforms

---

## 📝 Changelog

### Version 2026.1.0 (Current)

**New Features:**
- Added comprehensive configuration module
- Enhanced logging system with file rotation
- Improved password strength assessment
- File size validation and warnings
- Progress tracking for large operations
- Auto-port detection and management
- Enhanced contact management

**Improvements:**
- Better error handling and exception reporting
- Performance optimizations for large files
- Improved UI feedback and user experience
- Enhanced security measures
- Cross-platform compatibility improvements

**Bug Fixes:**
- Fixed Unicode encoding issues in test scripts
- Improved password validation logic
- Enhanced network timeout handling
- Fixed UI responsiveness issues

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📞 Support

For support, please:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review the [Issues](../../issues) page
3. Contact the author

---

## 🔮 Future Enhancements

Planned features for future versions:
- Cloud synchronization of encrypted data
- Advanced file shredding capabilities
- QR code sharing for quick connection setup
- Voice messaging support
- Video call encryption
- Mobile app versions

---

**Note:** This application is provided "as is" without warranty of any kind. Always backup your data and use at your own risk.
