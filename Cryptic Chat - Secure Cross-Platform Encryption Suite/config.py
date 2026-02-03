"""
Configuration file for Cryptic Chat - Secure Cross-Platform Encryption Suite
This file contains all application settings and constants
"""

import os
from datetime import datetime

# ==================================================
# APPLICATION INFORMATION
# ==================================================
APP_NAME = "Cryptic Chat - Secure Cross-Platform Encryption Suite"
APP_VERSION = "2026.1.0"
APP_AUTHOR = "Aryan Chavan"
APP_DESCRIPTION = "A comprehensive Python-based encryption and secure messaging application"

# ==================================================
# DATABASE SETTINGS
# ==================================================
TEXT_DB = "textdecrypt_pass.csv"
FILE_DB = "file_and_folder_decrypt_key.csv"
CONTACTS_DB = "saved_contacts.json"
MESSAGES_DB = "messages.json"

# ==================================================
# ENCRYPTION SETTINGS
# ==================================================
AES_KEY_LENGTH = 32  # 256 bits
AES_NONCE_LENGTH = 12  # GCM recommended length
AES_SALT_LENGTH = 16  # Secure salt size
PBKDF2_ITERATIONS = 300000  # Secure iteration count (NIST recommended)
PBKDF2_HASH_ALGORITHM = "sha256"

# ==================================================
# NETWORK SETTINGS
# ==================================================
DEFAULT_PORT = 5050
DEFAULT_PASSWORD = "SecureCrypto2026!"
CONNECTION_TIMEOUT = 10  # Seconds
BUFFER_SIZE = 65536  # 64KB buffer
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10MB maximum message size

# ==================================================
# FILE ENCRYPTION SETTINGS
# ==================================================
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB maximum file size
ENCRYPTION_EXTENSION = ".enc"

# ==================================================
# LOGGING SETTINGS
# ==================================================
LOG_FILE = "cryptic_chat.log"
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
BACKUP_COUNT = 5  # Keep 5 old log files

# ==================================================
# UI SETTINGS
# ==================================================
WINDOW_TITLE = "Cryptic Chat - Secure Cross-Platform Encryption Suite"
MAIN_WINDOW_SIZE = "900x700"
TEXT_WINDOW_SIZE = "800x600"
FILE_WINDOW_SIZE = "800x600"
MESSAGING_WINDOW_SIZE = "1000x750"
HISTORY_WINDOW_SIZE = "900x600"
TECHNOLOGY_WINDOW_SIZE = "900x700"

# ==================================================
# PASSWORD STRENGTH REQUIREMENTS
# ==================================================
MIN_PASSWORD_LENGTH = 8
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_DIGITS = True
REQUIRE_SPECIAL_CHARS = True
SPECIAL_CHARACTERS = "!@#$%^&*()_+=-[]{}|;:,.<>?"

# ==================================================
# DIRECTORY SETTINGS
# ==================================================
def get_app_data_dir():
    """Get the application data directory"""
    if os.name == 'nt':  # Windows
        return os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'CrypticChat')
    elif os.name == 'posix':  # macOS/Linux
        return os.path.join(os.path.expanduser('~'), '.crypticchat')
    else:
        return os.path.join(os.path.expanduser('~'), 'CrypticChat')

def ensure_directories():
    """Ensure all required directories exist"""
    app_dir = get_app_data_dir()
    if not os.path.exists(app_dir):
        os.makedirs(app_dir)

# ==================================================
# VALIDATION SETTINGS
# ==================================================
VALID_IP_REGEX = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
VALID_PORT_RANGE = (1024, 65535)

# ==================================================
# SECURITY WARNINGS
# ==================================================
SECURITY_WARNINGS = {
    "weak_password": "Warning: Your password is too weak. Use at least 8 characters with uppercase, lowercase, digits, and special characters.",
    "default_password": "Warning: You are using the default password. Please change it for better security.",
    "large_file": "Warning: This file is very large. Encryption may take some time.",
    "network_timeout": "Warning: Connection timed out. The message has been saved as pending.",
    "port_in_use": "Warning: Port is already in use. Trying another port..."
}

# ==================================================
# PERFORMANCE SETTINGS
# ==================================================
MAX_CONCURRENT_ENCRYPTIONS = 4  # Maximum parallel file encryption operations
CHUNK_SIZE = 64 * 1024  # 64KB chunks for file processing
