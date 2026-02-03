import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os, base64, hashlib, csv, re, time, socket, threading, platform, json, subprocess
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==================================================
# CSV DATABASE FILES
# ==================================================
TEXT_DB = "textdecrypt_pass.csv"
FILE_DB = "file_and_folder_decrypt_key.csv"
CONTACTS_DB = "saved_contacts.json"
MESSAGES_DB = "messages.json"



# ==================================================
# KEY MANAGEMENT
# ==================================================
def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def save_text_entry(msg_id, password, encrypted_text):
    """Save text encryption entry to textdecrypt_pass.csv"""
    exists = os.path.exists(TEXT_DB)
    with open(TEXT_DB, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["msg_id", "password_hash", "encrypted_text", "timestamp"])
        w.writerow([msg_id, hash_key(password), encrypted_text, time.ctime()])

def save_file_entry(entry_type, name, password):
    """Save file/folder encryption entry to file_and_folder_decrypt_key.csv"""
    exists = os.path.exists(FILE_DB)
    with open(FILE_DB, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["type", "name", "password_hash", "timestamp"])
        w.writerow([entry_type, name, hash_key(password), time.ctime()])

def verify_file_key(entry_type, name, password):
    """Verify password for file/folder decryption"""
    if not os.path.exists(FILE_DB):
        return False
    with open(FILE_DB, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["type"] == entry_type and row["name"] == name:
                return row["password_hash"] == hash_key(password)
    return False

def get_all_text_entries():
    """Get all text encryption entries"""
    entries = []
    if os.path.exists(TEXT_DB):
        with open(TEXT_DB, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                entries.append(row)
    return entries

def get_all_file_entries():
    """Get all file/folder encryption entries"""
    entries = []
    if os.path.exists(FILE_DB):
        with open(FILE_DB, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                entries.append(row)
    return entries

# ==================================================
# PASSWORD STRENGTH
# ==================================================
class PasswordStrength:
    @staticmethod
    def score(p):
        return sum([
            len(p) >= 12,
            bool(re.search(r"[A-Z]", p)),
            bool(re.search(r"[a-z]", p)),
            bool(re.search(r"[0-9]", p)),
            bool(re.search(r"[!@#$%^&*()_+=\-]", p))
        ])

# ==================================================
# AES-256-GCM CORE
# ==================================================
class AES256:
    @staticmethod
    def derive_key(password, salt):
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=300_000
        ).derive(password.encode())

    @staticmethod
    def encrypt(data: bytes, password: str) -> bytes:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = AES256.derive_key(password, salt)
        ct = AESGCM(key).encrypt(nonce, data, None)
        return salt + nonce + ct

    @staticmethod
    def decrypt(blob: bytes, password: str) -> bytes:
        salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
        key = AES256.derive_key(password, salt)
        return AESGCM(key).decrypt(nonce, ct, None)

# ==================================================
# TEXT / FILE / FOLDER CRYPTO
# ==================================================
class CryptoOps:
    @staticmethod
    def encrypt_text(text, password):
        """Encrypt text with password only (no key verification needed for decryption)"""
        msg_id = f"Message_{int(time.time())}"
        blob = AES256.encrypt(text.encode(), password)
        encrypted_b64 = base64.b64encode(blob).decode()
        save_text_entry(msg_id, password, encrypted_b64)
        return msg_id, encrypted_b64

    @staticmethod
    def decrypt_text(cipher, password):
        """Decrypt text with password only (no key verification)"""
        blob = base64.b64decode(cipher)
        return AES256.decrypt(blob, password).decode()

    @staticmethod
    def encrypt_file(path, password):
        with open(path, "rb") as f:
            data = f.read()
        enc = AES256.encrypt(data, password)
        enc_path = path + ".enc"
        with open(enc_path, "wb") as f:
            f.write(enc)
        save_file_entry("file", os.path.basename(path), password)
        os.remove(path)
        return enc_path

    @staticmethod
    def decrypt_file(path, password):
        name = os.path.basename(path[:-4])
        if not verify_file_key("file", name, password):
            raise ValueError("Invalid password")
        with open(path, "rb") as f:
            data = f.read()
        dec = AES256.decrypt(data, password)
        original_path = path[:-4]
        with open(original_path, "wb") as f:
            f.write(dec)
        os.remove(path)
        return original_path

    @staticmethod
    def encrypt_folder(folder, password):
        save_file_entry("folder", os.path.basename(folder), password)
        encrypted_files = []
        for root, _, files in os.walk(folder):
            for file in files:
                if not file.endswith(".enc"):
                    file_path = os.path.join(root, file)
                    enc_path = CryptoOps.encrypt_file(file_path, password)
                    encrypted_files.append(enc_path)
        return encrypted_files

    @staticmethod
    def decrypt_folder(folder, password):
        name = os.path.basename(folder)
        if not verify_file_key("folder", name, password):
            raise ValueError("Invalid password")
        decrypted_files = []
        for root, _, files in os.walk(folder):
            for file in files:
                if file.endswith(".enc"):
                    enc_path = os.path.join(root, file)
                    dec_path = CryptoOps.decrypt_file(enc_path, password)
                    decrypted_files.append(dec_path)
        return decrypted_files

# ==================================================
# CONTACT AND MESSAGE MANAGEMENT
# ==================================================
class ContactManager:
    @staticmethod
    def load_contacts():
        """Load saved contacts from JSON file"""
        if os.path.exists(CONTACTS_DB):
            try:
                with open(CONTACTS_DB, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return {"saved": [], "blocked": []}
    
    @staticmethod
    def save_contacts(contacts):
        """Save contacts to JSON file"""
        with open(CONTACTS_DB, 'w', encoding='utf-8') as f:
            json.dump(contacts, f, indent=2)
    
    @staticmethod
    def add_contact(ip, port=5050, name=None):
        """Add a contact to saved list"""
        contacts = ContactManager.load_contacts()
        # Check if already exists
        for contact in contacts["saved"]:
            if contact["ip"] == ip:
                return False
        contact = {
            "ip": ip,
            "port": port,
            "name": name or ip,
            "timestamp": time.ctime()
        }
        contacts["saved"].append(contact)
        ContactManager.save_contacts(contacts)
        return True
    
    @staticmethod
    def block_contact(ip):
        """Block a contact"""
        contacts = ContactManager.load_contacts()
        # Remove from saved if present
        contacts["saved"] = [c for c in contacts["saved"] if c["ip"] != ip]
        # Add to blocked if not already
        if ip not in [c["ip"] for c in contacts["blocked"]]:
            contacts["blocked"].append({
                "ip": ip,
                "timestamp": time.ctime()
            })
        ContactManager.save_contacts(contacts)
    
    @staticmethod
    def unblock_contact(ip):
        """Unblock a contact"""
        contacts = ContactManager.load_contacts()
        contacts["blocked"] = [c for c in contacts["blocked"] if c["ip"] != ip]
        ContactManager.save_contacts(contacts)
    
    @staticmethod
    def is_blocked(ip):
        """Check if IP is blocked"""
        contacts = ContactManager.load_contacts()
        return any(c["ip"] == ip for c in contacts["blocked"])
    
    @staticmethod
    def get_saved_contacts():
        """Get all saved contacts"""
        return ContactManager.load_contacts()["saved"]
    
    @staticmethod
    def get_blocked_contacts():
        """Get all blocked contacts"""
        return ContactManager.load_contacts()["blocked"]


class MessageStorage:
    @staticmethod
    def load_messages():
        """Load saved messages from JSON file"""
        if os.path.exists(MESSAGES_DB):
            try:
                with open(MESSAGES_DB, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    @staticmethod
    def save_messages(messages):
        """Save messages to JSON file"""
        with open(MESSAGES_DB, 'w', encoding='utf-8') as f:
            json.dump(messages, f, indent=2)
    
    @staticmethod
    def save_message(sender_ip, receiver_ip, message, timestamp, direction, status="sent"):
        """Save a message to storage"""
        messages = MessageStorage.load_messages()
        if sender_ip not in messages:
            messages[sender_ip] = []
        if receiver_ip not in messages:
            messages[receiver_ip] = []
        
        msg_data = {
            "message": message,
            "timestamp": timestamp,
            "direction": direction,  # "sent" or "received"
            "status": status
        }
        
        messages[sender_ip].append(msg_data)
        if sender_ip != receiver_ip:
            messages[receiver_ip].append(msg_data)
        
        MessageStorage.save_messages(messages)
    
    @staticmethod
    def get_messages_with_contact(ip):
        """Get all messages with a specific contact"""
        messages = MessageStorage.load_messages()
        return messages.get(ip, [])
    
    @staticmethod
    def delete_messages_with_contact(ip):
        """Delete all messages with a specific contact"""
        messages = MessageStorage.load_messages()
        if ip in messages:
            del messages[ip]
        MessageStorage.save_messages(messages)


# ==================================================
# 🌐 SECURE NETWORK TRANSFER (Cross-Platform)
# ==================================================
class NetworkCrypto:
    """Secure messaging that works on Windows, Linux, and all Linux distros"""
    
    @staticmethod
    def get_local_ip():
        """Get local IP address cross-platform"""
        system = platform.system().lower()
        try:
            if system == "windows":
                # Windows method
                result = subprocess.run(["powershell", "-Command", 
                    "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike '127.*'}).IPAddress"],
                    capture_output=True, text=True)
                ip = result.stdout.strip().split('\n')[0]
                if ip:
                    return ip
            else:
                # Linux/Mac method
                result = subprocess.run(["hostname", "-I"], capture_output=True, text=True)
                ip = result.stdout.strip().split()[0]
                if ip:
                    return ip
        except:
            pass
        
        # Fallback: Use socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    @staticmethod
    def is_port_available(port):
        """Check if port is available"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", port))
                return True
            except:
                return False
    
    @staticmethod
    def find_available_port(start_port=5050):
        """Find an available port"""
        port = start_port
        while port < 65535:
            if NetworkCrypto.is_port_available(port):
                return port
            port += 1
        return None

    @staticmethod
    def send(ip, port, message, password):
        """Send secure encrypted message with offline storage support"""
        blob = AES256.encrypt(message.encode(), password)
        encoded_data = base64.b64encode(blob)
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            try:
                s.connect((ip, port))
                s.sendall(encoded_data)
                return True
            except socket.timeout:
                raise ConnectionError("Connection timed out - message saved for later delivery")
            except ConnectionRefusedError:
                raise ConnectionError("Connection refused - receiver not online, message saved for later delivery")
            except Exception as e:
                raise ConnectionError(f"Send failed: {str(e)} - message saved for later delivery")

    @staticmethod
    def listen(port, password, callback, stop_event=None):
        """Listen for secure encrypted messages"""
        def server():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind(("0.0.0.0", port))
                    s.listen(1)
                    s.settimeout(1.0)  # Allow checking stop_event
                    
                    while stop_event is None or not stop_event.is_set():
                        try:
                            conn, addr = s.accept()
                            with conn:
                                data = b""
                                while True:
                                    chunk = conn.recv(65536)
                                    if not chunk:
                                        break
                                    data += chunk
                                
                                if data:
                                    try:
                                        msg = AES256.decrypt(base64.b64decode(data), password).decode()
                                        callback(addr[0], msg, None)
                                    except Exception as e:
                                        callback(addr[0], None, f"Decryption failed: {str(e)}")
                        except socket.timeout:
                            continue
                        except Exception as e:
                            if stop_event is None or not stop_event.is_set():
                                callback(None, None, f"Server error: {str(e)}")
                except Exception as e:
                    callback(None, None, f"Bind error: {str(e)}")
        
        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        return thread

# ==================================================
# GUI - MAIN MENU
# ==================================================
class SecureCryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Crypto Suite 2026 - Cross-Platform Edition BY aryan chavan")
        
        # Get screen dimensions for responsive sizing
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        
        # Set window size to 70% of screen dimensions (max 900x700, min 600x500)
        window_width = min(int(screen_width * 0.7), 900)
        window_height = min(int(screen_height * 0.7), 700)
        window_width = max(window_width, 600)
        window_height = max(window_height, 500)
        
        # Center the window
        x_pos = (screen_width - window_width) // 2
        y_pos = (screen_height - window_height) // 2
        
        self.root.geometry(f"{window_width}x{window_height}+{x_pos}+{y_pos}")
        self.root.minsize(600, 500)  # Minimum size constraint
        self.root.maxsize(1200, 900)  # Maximum size constraint
        
        # Platform info
        self.platform_info = f"{platform.system()} {platform.release()}"
        
        ttk.Style().theme_use("clam")
        
        # Create scrollable container for main window
        canvas = tk.Canvas(root)
        scrollbar = ttk.Scrollbar(root, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas)
        
        scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack scrollable container
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Title
        ttk.Label(scroll_frame, text="🔐 Secure Crypto Suite 2026 BY aryan chavan ",
                  font=("Segoe UI", 24, "bold")).pack(pady=10)
        
        ttk.Label(scroll_frame, text=f"Platform: {self.platform_info}",
                  font=("Segoe UI", 10)).pack()
        
        # Main Menu Frame
        menu_frame = tk.Frame(scroll_frame)
        menu_frame.pack(pady=30)
        
        ttk.Label(menu_frame, text="Select Operation Mode:",
                  font=("Segoe UI", 14, "bold")).pack(pady=10)
        
        # Menu Buttons
        btn_frame = tk.Frame(menu_frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="📝 Text Encryption/Decryption",
                   command=self.open_text_window, width=40).pack(pady=10)
        
        ttk.Button(btn_frame, text="📁 File & Folder Encryption/Decryption",
                   command=self.open_file_window, width=40).pack(pady=10)
        
        ttk.Button(btn_frame, text="📡 Secure Messaging",
                   command=self.open_messaging_window, width=40).pack(pady=10)
        
        ttk.Button(btn_frame, text="📊 View Encryption History",
                   command=self.open_history_window, width=40).pack(pady=10)
        
        ttk.Button(btn_frame, text="💻 2026 Technologies",
                   command=self.show_technologies, width=40).pack(pady=10)
        
        # Status
        self.status_label = ttk.Label(scroll_frame, text="Ready", font=("Segoe UI", 10))
        self.status_label.pack(pady=10)
        
        # Footer
        ttk.Label(scroll_frame, text="Cross-Platform Secure Communication | Windows | Linux | macOS",
                  font=("Segoe UI", 9, "italic"), foreground="gray").pack(pady=5)

    # ==================================================
    # TEXT ENCRYPTION WINDOW
    # ==================================================
    def open_text_window(self):
        window = tk.Toplevel(self.root)
        window.title("Text Encryption/Decryption")
        
        # Responsive sizing for text window
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = min(int(screen_width * 0.65), 800)
        window_height = min(int(screen_height * 0.65), 600)
        window_width = max(window_width, 600)
        window_height = max(window_height, 500)
        
        x_pos = (screen_width - window_width) // 2
        y_pos = (screen_height - window_height) // 2
        
        window.geometry(f"{window_width}x{window_height}+{x_pos}+{y_pos}")
        window.minsize(600, 500)
        window.maxsize(1000, 700)
        
        # Create scrollable container for text window
        canvas = tk.Canvas(window)
        scrollbar = ttk.Scrollbar(window, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas)
        
        scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack scrollable container
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        ttk.Label(scroll_frame, text="📝 Text Encryption/Decryption",
                  font=("Segoe UI", 18, "bold")).pack(pady=10)
        
        # Text Input
        ttk.Label(scroll_frame, text="Enter Text:").pack(anchor="w", padx=20)
        text_input = tk.Text(scroll_frame, height=6, font=("Consolas", 11))
        text_input.pack(fill="x", padx=20, pady=5)
        
        # Password
        pass_frame = tk.Frame(window)
        pass_frame.pack(pady=10)
        
        ttk.Label(pass_frame, text="Password:").grid(row=0, column=0, padx=5)
        password_var = tk.StringVar()
        ttk.Entry(pass_frame, textvariable=password_var, show="*", width=30).grid(row=0, column=1, padx=5)
        
        strength_label = ttk.Label(pass_frame, text="Strength: –")
        strength_label.grid(row=0, column=2, padx=10)
        
        def update_strength(*_):
            levels = ["Very Weak","Weak","OK","Strong","Very Strong","Excellent"]
            score = PasswordStrength.score(password_var.get())
            strength_label.config(text=f"Strength: {levels[score]}")
        
        password_var.trace_add("write", update_strength)
        
        # Buttons
        btn_frame = tk.Frame(window)
        btn_frame.pack(pady=10)
        
        result_text = tk.Text(window, height=10, font=("Consolas", 10))
        result_text.pack(fill="x", padx=20, pady=10)
        
        def encrypt():
            text = text_input.get("1.0", tk.END).strip()
            pwd = password_var.get()
            if not text or not pwd:
                messagebox.showerror("Error", "Please enter both text and password")
                return
            try:
                msg_id, cipher = CryptoOps.encrypt_text(text, pwd)
                result_text.delete("1.0", tk.END)
                result_text.insert(tk.END, f"Message ID: {msg_id}\n")
                result_text.insert(tk.END, f"Encrypted (copy this):\n{cipher}")
                self.status_label.config(text=f"Text encrypted - Saved to {TEXT_DB}")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        
        def decrypt():
            cipher = text_input.get("1.0", tk.END).strip()
            pwd = password_var.get()
            if not cipher or not pwd:
                messagebox.showerror("Error", "Please enter encrypted text and password")
                return
            try:
                # Remove any message ID prefix if present
                lines = cipher.split('\n')
                if len(lines) > 1 and lines[0].startswith('Message_'):
                    cipher = '\n'.join(lines[1:]).strip()
                plain = CryptoOps.decrypt_text(cipher, pwd)
                result_text.delete("1.0", tk.END)
                result_text.insert(tk.END, f"Decrypted:\n{plain}")
                self.status_label.config(text="Text decrypted successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        
        ttk.Button(btn_frame, text="Encrypt", command=encrypt).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Decrypt", command=decrypt).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="Clear", command=lambda: [text_input.delete("1.0", tk.END), result_text.delete("1.0", tk.END)]).grid(row=0, column=2, padx=5)

    # ==================================================
    # FILE/FOLDER ENCRYPTION WINDOW
    # ==================================================
    def open_file_window(self):
        window = tk.Toplevel(self.root)
        window.title("File & Folder Encryption/Decryption")
        
        # Responsive sizing for file window
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = min(int(screen_width * 0.65), 800)
        window_height = min(int(screen_height * 0.65), 600)
        window_width = max(window_width, 600)
        window_height = max(window_height, 500)
        
        x_pos = (screen_width - window_width) // 2
        y_pos = (screen_height - window_height) // 2
        
        window.geometry(f"{window_width}x{window_height}+{x_pos}+{y_pos}")
        window.minsize(600, 500)
        window.maxsize(1000, 700)
        
        # Create scrollable container for file window
        canvas = tk.Canvas(window)
        scrollbar = ttk.Scrollbar(window, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas)
        
        scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack scrollable container
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        ttk.Label(scroll_frame, text="📁 File & Folder Encryption/Decryption",
                   font=("Segoe UI", 18, "bold")).pack(pady=10)
        
        # Password
        pass_frame = tk.Frame(scroll_frame)
        pass_frame.pack(pady=10)
        
        ttk.Label(pass_frame, text="Password:").grid(row=0, column=0, padx=5)
        password_var = tk.StringVar()
        ttk.Entry(pass_frame, textvariable=password_var, show="*", width=30).grid(row=0, column=1, padx=5)
        
        # Selected path display
        path_frame = tk.Frame(window)
        path_frame.pack(pady=10, fill="x", padx=20)
        
        ttk.Label(path_frame, text="Selected:").pack(anchor="w")
        path_label = ttk.Label(path_frame, text="None", wraplength=700)
        path_label.pack(anchor="w")
        
        selected_path = [None]
        
        def select_file():
            f = filedialog.askopenfilename()
            if f:
                selected_path[0] = f
                path_label.config(text=f)
        
        def select_folder():
            d = filedialog.askdirectory()
            if d:
                selected_path[0] = d
                path_label.config(text=d)
        
        # Buttons
        btn_frame = tk.Frame(window)
        btn_frame.pack(pady=10)
        
        result_text = tk.Text(window, height=12, font=("Consolas", 10))
        result_text.pack(fill="x", padx=20, pady=10)
        
        def encrypt_file():
            if not selected_path[0]:
                messagebox.showerror("Error", "Please select a file")
                return
            pwd = password_var.get()
            if not pwd:
                messagebox.showerror("Error", "Please enter password")
                return
            try:
                enc_path = CryptoOps.encrypt_file(selected_path[0], pwd)
                result_text.insert(tk.END, f"✓ File encrypted: {enc_path}\n")
                result_text.insert(tk.END, f"✓ Saved to {FILE_DB}\n")
                self.status_label.config(text=f"File encrypted - {os.path.basename(enc_path)}")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        
        def decrypt_file():
            if not selected_path[0]:
                messagebox.showerror("Error", "Please select a file")
                return
            pwd = password_var.get()
            if not pwd:
                messagebox.showerror("Error", "Please enter password")
                return
            try:
                dec_path = CryptoOps.decrypt_file(selected_path[0], pwd)
                result_text.insert(tk.END, f"✓ File decrypted: {dec_path}\n")
                self.status_label.config(text=f"File decrypted - {os.path.basename(dec_path)}")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        
        def encrypt_folder():
            if not selected_path[0]:
                messagebox.showerror("Error", "Please select a folder")
                return
            pwd = password_var.get()
            if not pwd:
                messagebox.showerror("Error", "Please enter password")
                return
            try:
                enc_files = CryptoOps.encrypt_folder(selected_path[0], pwd)
                result_text.insert(tk.END, f"✓ Folder encrypted: {selected_path[0]}\n")
                result_text.insert(tk.END, f"✓ {len(enc_files)} files encrypted\n")
                result_text.insert(tk.END, f"✓ Saved to {FILE_DB}\n")
                self.status_label.config(text=f"Folder encrypted - {len(enc_files)} files")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        
        def decrypt_folder():
            if not selected_path[0]:
                messagebox.showerror("Error", "Please select a folder")
                return
            pwd = password_var.get()
            if not pwd:
                messagebox.showerror("Error", "Please enter password")
                return
            try:
                dec_files = CryptoOps.decrypt_folder(selected_path[0], pwd)
                result_text.insert(tk.END, f"✓ Folder decrypted: {selected_path[0]}\n")
                result_text.insert(tk.END, f"✓ {len(dec_files)} files decrypted\n")
                self.status_label.config(text=f"Folder decrypted - {len(dec_files)} files")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        
        ttk.Button(btn_frame, text="Select File", command=select_file).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Select Folder", command=select_folder).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="Encrypt File", command=encrypt_file).grid(row=0, column=2, padx=5)
        ttk.Button(btn_frame, text="Decrypt File", command=decrypt_file).grid(row=0, column=3, padx=5)
        ttk.Button(btn_frame, text="Encrypt Folder", command=encrypt_folder).grid(row=0, column=4, padx=5)
        ttk.Button(btn_frame, text="Decrypt Folder", command=decrypt_folder).grid(row=0, column=5, padx=5)

    # ==================================================
    # SECURE MESSAGING WINDOW
    # ==================================================
    def open_messaging_window(self):
        window = tk.Toplevel(self.root)
        window.title("Secure Messaging")
        
        # Responsive sizing for messaging window
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = min(int(screen_width * 0.75), 1000)
        window_height = min(int(screen_height * 0.75), 750)
        window_width = max(window_width, 800)
        window_height = max(window_height, 600)
        
        x_pos = (screen_width - window_width) // 2
        y_pos = (screen_height - window_height) // 2
        
        window.geometry(f"{window_width}x{window_height}+{x_pos}+{y_pos}")
        window.minsize(800, 600)
        window.maxsize(1200, 800)
        
        ttk.Label(window, text="📡 Secure Cross-Platform Messaging",
                  font=("Segoe UI", 18, "bold")).pack(pady=10)
        
        # Network Info
        local_ip = NetworkCrypto.get_local_ip()
        ttk.Label(window, text=f"Your IP: {local_ip}",
                  font=("Segoe UI", 12)).pack()
        
        # Main Container with Notebook (Tabs)
        notebook = ttk.Notebook(window)
        notebook.pack(fill="both", expand=True, padx=20, pady=10)
        
        # ==================== CONTACTS TAB ====================
        contacts_tab = tk.Frame(notebook)
        notebook.add(contacts_tab, text="Contacts")
        
        # Saved Contacts
        saved_frame = tk.LabelFrame(contacts_tab, text="Saved Contacts", padx=10, pady=10)
        saved_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        saved_tree = ttk.Treeview(saved_frame, columns=("IP", "Port", "Name", "Date"), show="headings")
        saved_tree.heading("IP", text="IP Address")
        saved_tree.heading("Port", text="Port")
        saved_tree.heading("Name", text="Name")
        saved_tree.heading("Date", text="Date Added")
        saved_tree.column("IP", width=150)
        saved_tree.column("Port", width=80)
        saved_tree.column("Name", width=150)
        saved_tree.column("Date", width=150)
        
        saved_scroll = ttk.Scrollbar(saved_frame, orient="vertical", command=saved_tree.yview)
        saved_tree.configure(yscrollcommand=saved_scroll.set)
        saved_scroll.pack(side="right", fill="y")
        saved_tree.pack(fill="both", expand=True)
        
        # Blocked Contacts
        blocked_frame = tk.LabelFrame(contacts_tab, text="Blocked Contacts", padx=10, pady=10)
        blocked_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        blocked_tree = ttk.Treeview(blocked_frame, columns=("IP", "Date"), show="headings")
        blocked_tree.heading("IP", text="IP Address")
        blocked_tree.heading("Date", text="Blocked On")
        blocked_tree.column("IP", width=200)
        blocked_tree.column("Date", width=150)
        
        blocked_scroll = ttk.Scrollbar(blocked_frame, orient="vertical", command=blocked_tree.yview)
        blocked_tree.configure(yscrollcommand=blocked_scroll.set)
        blocked_scroll.pack(side="right", fill="y")
        blocked_tree.pack(fill="both", expand=True)
        
        # Contact Management Buttons
        contact_btn_frame = tk.Frame(contacts_tab)
        contact_btn_frame.pack(pady=10)
        
        # ==================== CHAT TAB ====================
        chat_tab = tk.Frame(notebook)
        notebook.add(chat_tab, text="Chat")
        
        # Left Sidebar: Controls and Settings (fixed width)
        sidebar_frame = tk.Frame(chat_tab, width=250)
        sidebar_frame.pack(side="left", fill="y", padx=10, pady=10)
        sidebar_frame.pack_propagate(False)  # Prevent shrinking
        
        # Contact List
        contact_list_frame = tk.LabelFrame(sidebar_frame, text="Chat with Contact", padx=10, pady=10)
        contact_list_frame.pack(fill="x", padx=5, pady=5)
        
        contact_list = tk.Listbox(contact_list_frame, width=25, height=8, font=("Segoe UI", 10))
        contact_list.pack(fill="both", expand=True)
        
        # Connection Settings
        conn_frame = tk.LabelFrame(sidebar_frame, text="Connection Settings", padx=10, pady=10)
        conn_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(conn_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=2)
        ip_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(conn_frame, textvariable=ip_var, width=15).grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(conn_frame, text="Port:").grid(row=1, column=0, padx=5, pady=2)
        port_var = tk.IntVar(value=5050)
        ttk.Entry(conn_frame, textvariable=port_var, width=15).grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(conn_frame, text="Password:").grid(row=2, column=0, padx=5, pady=2)
        password_var = tk.StringVar()
        ttk.Entry(conn_frame, textvariable=password_var, show="*", width=15).grid(row=2, column=1, padx=5, pady=2)
        
        # Control Buttons
        button_frame = tk.LabelFrame(sidebar_frame, text="Controls", padx=10, pady=10)
        button_frame.pack(fill="x", padx=5, pady=5)
        
        # Right: Chat Area (expands)
        chat_container = tk.Frame(chat_tab)
        chat_container.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # Chat Display
        chat_frame = tk.LabelFrame(chat_container, text="Chat", padx=10, pady=10)
        chat_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        chat_text = tk.Text(chat_frame, height=15, font=("Segoe UI", 10))
        chat_text.pack(fill="both", expand=True)
        
        chat_scroll = ttk.Scrollbar(chat_frame, orient="vertical", command=chat_text.yview)
        chat_text.configure(yscrollcommand=chat_scroll.set)
        chat_scroll.pack(side="right", fill="y")
        
        # Message Input
        msg_frame = tk.Frame(chat_container)
        msg_frame.pack(fill="x", padx=5, pady=5)
        
        msg_text = tk.Text(msg_frame, height=3, font=("Segoe UI", 10))
        msg_text.pack(side="left", fill="both", expand=True, padx=5)
        
        # Server control
        server_thread = [None]
        stop_event = threading.Event()
        
        # ==================== FUNCTIONS ====================
        def refresh_contacts():
            saved_tree.delete(*saved_tree.get_children())
            for contact in ContactManager.get_saved_contacts():
                saved_tree.insert("", "end", values=(
                    contact["ip"],
                    contact["port"],
                    contact["name"],
                    contact["timestamp"]
                ))
            
            blocked_tree.delete(*blocked_tree.get_children())
            for contact in ContactManager.get_blocked_contacts():
                blocked_tree.insert("", "end", values=(
                    contact["ip"],
                    contact["timestamp"]
                ))
            
            contact_list.delete(0, tk.END)
            for contact in ContactManager.get_saved_contacts():
                contact_list.insert(tk.END, f"{contact['name']} ({contact['ip']})")
        
        def log(msg):
            chat_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
            chat_text.see(tk.END)
        
        def send_message():
            msg = msg_text.get("1.0", tk.END).strip()
            pwd = password_var.get()
            if not msg or not pwd:
                messagebox.showerror("Error", "Please enter message and password")
                return
            
            ip = ip_var.get()
            port = port_var.get()
            
            if ContactManager.is_blocked(ip):
                messagebox.showerror("Error", "Cannot send message to blocked IP")
                return
            
            try:
                NetworkCrypto.send(ip, port, msg, pwd)
                log(f"📤 Me: {msg}")
                MessageStorage.save_message(local_ip, ip, msg, time.ctime(), "sent", "delivered")
                msg_text.delete("1.0", tk.END)
            except Exception as e:
                log(f"❌ Send failed: {str(e)}")
                MessageStorage.save_message(local_ip, ip, msg, time.ctime(), "sent", "pending")
                messagebox.showerror("Error", str(e))
        
        def start_listening():
            if server_thread[0] and server_thread[0].is_alive():
                log("Already listening")
                return
            
            pwd = password_var.get()
            if not pwd:
                messagebox.showerror("Error", "Please enter password for decryption")
                return
            
            stop_event.clear()
            port = port_var.get()
            
            def on_receive(sender_ip, msg, error):
                if error:
                    log(f"❌ Error: {error}")
                else:
                    if not ContactManager.is_blocked(sender_ip):
                        log(f"📥 {sender_ip}: {msg}")
                        MessageStorage.save_message(sender_ip, local_ip, msg, time.ctime(), "received")
                    else:
                        log(f"🚫 Blocked message from {sender_ip}")
            
            server_thread[0] = NetworkCrypto.listen(port, pwd, on_receive, stop_event)
            log(f"🔊 Listening on port {port}...")
            log(f"   Your IP: {local_ip}")
        
        def stop_listening():
            stop_event.set()
            log("🛑 Stopped listening")
        
        def auto_port():
            port = NetworkCrypto.find_available_port()
            if port:
                port_var.set(port)
                log(f"✓ Found available port: {port}")
            else:
                log("❌ No available port found")
        
        def add_contact():
            ip = ip_var.get()
            port = port_var.get()
            name = tk.simpledialog.askstring("Add Contact", "Enter contact name (optional):")
            if ContactManager.add_contact(ip, port, name):
                refresh_contacts()
                messagebox.showinfo("Success", "Contact added successfully")
            else:
                messagebox.showwarning("Warning", "Contact already exists")
        
        def block_selected_contact():
            selected = saved_tree.selection()
            if selected:
                item = saved_tree.item(selected)
                ip = item["values"][0]
                ContactManager.block_contact(ip)
                refresh_contacts()
                messagebox.showinfo("Success", f"Contact {ip} blocked")
        
        def unblock_selected_contact():
            selected = blocked_tree.selection()
            if selected:
                item = blocked_tree.item(selected)
                ip = item["values"][0]
                ContactManager.unblock_contact(ip)
                refresh_contacts()
                messagebox.showinfo("Success", f"Contact {ip} unblocked")
        
        def select_contact(event):
            try:
                index = contact_list.curselection()[0]
                contacts = ContactManager.get_saved_contacts()
                if index < len(contacts):
                    contact = contacts[index]
                    ip_var.set(contact["ip"])
                    port_var.set(contact["port"])
                    # Load chat history
                    chat_text.delete("1.0", tk.END)
                    messages = MessageStorage.get_messages_with_contact(contact["ip"])
                    for msg in messages:
                        time_str = msg["timestamp"].split()[3]
                        if msg["direction"] == "sent":
                            chat_text.insert(tk.END, f"[{time_str}] 📤 Me: {msg['message']}\n")
                        else:
                            chat_text.insert(tk.END, f"[{time_str}] 📥 {contact['name']}: {msg['message']}\n")
                    chat_text.see(tk.END)
            except:
                pass
        
        def delete_contact():
            selected = saved_tree.selection()
            if selected:
                item = saved_tree.item(selected)
                ip = item["values"][0]
                if messagebox.askyesno("Confirm Delete", f"Delete contact {ip}?"):
                    contacts = ContactManager.load_contacts()
                    contacts["saved"] = [c for c in contacts["saved"] if c["ip"] != ip]
                    ContactManager.save_contacts(contacts)
                    MessageStorage.delete_messages_with_contact(ip)
                    refresh_contacts()
                    chat_text.delete("1.0", tk.END)
                    messagebox.showinfo("Success", "Contact deleted")
        
        # ==================== AUTO SETUP FUNCTION ====================
        def setup_auto_messaging():
            # Auto-detect available port
            auto_port()
            
            # Auto-start listening with default password if not set
            if not password_var.get():
                # Set a default secure password (can be changed by user)
                default_pwd = "SecureCrypto2026!"
                password_var.set(default_pwd)
            
            # Auto-start listening
            start_listening()
            
            # Check for pending messages and attempt to deliver
            check_pending_messages()
        
        def check_pending_messages():
            # Load all pending messages and attempt to resend
            messages = MessageStorage.load_messages()
            for contact_ip, msgs in messages.items():
                pending = [msg for msg in msgs if msg.get("status") == "pending"]
                if pending:
                    log(f"Checking pending messages for {contact_ip}...")
                    for msg in pending:
                        try:
                            # Attempt to send pending message
                            NetworkCrypto.send(contact_ip, port_var.get(), msg["message"], password_var.get())
                            # Update message status to delivered
                            msg["status"] = "delivered"
                            log(f"✓ Pending message delivered to {contact_ip}")
                        except:
                            log(f"⚠️ Still unable to deliver pending message to {contact_ip}")
                    MessageStorage.save_messages(messages)
        
        # Now create the buttons (functions are defined now)
        ttk.Button(button_frame, text="Start Listening", command=start_listening).pack(fill="x", padx=5, pady=2)
        ttk.Button(button_frame, text="Stop Listening", command=stop_listening).pack(fill="x", padx=5, pady=2)
        ttk.Button(button_frame, text="Auto Port", command=auto_port).pack(fill="x", padx=5, pady=2)
        ttk.Button(button_frame, text="Clear Chat", command=lambda: chat_text.delete("1.0", tk.END)).pack(fill="x", padx=5, pady=2)
        
        ttk.Button(msg_frame, text="Send", command=send_message).pack(side="left", padx=5)
        
        # ==================== BUTTONS ====================
        # Contact Management Buttons
        ttk.Button(contact_btn_frame, text="Add Contact", command=add_contact).grid(row=0, column=0, padx=5)
        ttk.Button(contact_btn_frame, text="Block Contact", command=block_selected_contact).grid(row=0, column=1, padx=5)
        ttk.Button(contact_btn_frame, text="Unblock Contact", command=unblock_selected_contact).grid(row=0, column=2, padx=5)
        ttk.Button(contact_btn_frame, text="Delete Contact", command=delete_contact).grid(row=0, column=3, padx=5)
        
        # ==================== BINDINGS ====================
        contact_list.bind("<<ListboxSelect>>", select_contact)
        
        # ==================== FUNCTIONS ====================
        def setup_auto_messaging():
            # Auto-detect available port
            auto_port()
            
            # Auto-start listening with default password if not set
            if not password_var.get():
                # Set a default secure password (can be changed by user)
                default_pwd = "SecureCrypto2026!"
                password_var.set(default_pwd)
            
            # Auto-start listening
            start_listening()
            
            # Check for pending messages and attempt to deliver
            check_pending_messages()
        
        def check_pending_messages():
            # Load all pending messages and attempt to resend
            messages = MessageStorage.load_messages()
            for contact_ip, msgs in messages.items():
                pending = [msg for msg in msgs if msg.get("status") == "pending"]
                if pending:
                    log(f"Checking pending messages for {contact_ip}...")
                    for msg in pending:
                        try:
                            # Attempt to send pending message
                            NetworkCrypto.send(contact_ip, port_var.get(), msg["message"], password_var.get())
                            # Update message status to delivered
                            msg["status"] = "delivered"
                            log(f"✓ Pending message delivered to {contact_ip}")
                        except:
                            log(f"⚠️ Still unable to deliver pending message to {contact_ip}")
                    MessageStorage.save_messages(messages)
        
        # ==================== INITIALIZATION ====================
        refresh_contacts()
        setup_auto_messaging()

    # ==================================================
    # HISTORY WINDOW
    # ==================================================
    def open_history_window(self):
        window = tk.Toplevel(self.root)
        window.title("Encryption History")
        
        # Responsive sizing for history window
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = min(int(screen_width * 0.7), 900)
        window_height = min(int(screen_height * 0.65), 600)
        window_width = max(window_width, 600)
        window_height = max(window_height, 500)
        
        x_pos = (screen_width - window_width) // 2
        y_pos = (screen_height - window_height) // 2
        
        window.geometry(f"{window_width}x{window_height}+{x_pos}+{y_pos}")
        window.minsize(600, 500)
        window.maxsize(1100, 700)
        
        ttk.Label(window, text="📊 Encryption History",
                  font=("Segoe UI", 18, "bold")).pack(pady=10)
        
        notebook = ttk.Notebook(window)
        notebook.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Text History Tab
        text_tab = tk.Frame(notebook)
        notebook.add(text_tab, text="Text Encryption History")
        
        text_tree = ttk.Treeview(text_tab, columns=("ID", "Hash", "Timestamp"), show="headings")
        text_tree.heading("ID", text="Message ID")
        text_tree.heading("Hash", text="Password Hash")
        text_tree.heading("Timestamp", text="Timestamp")
        text_tree.column("ID", width=200)
        text_tree.column("Hash", width=300)
        text_tree.column("Timestamp", width=200)
        
        scrollbar1 = ttk.Scrollbar(text_tab, orient="vertical", command=text_tree.yview)
        text_tree.configure(yscrollcommand=scrollbar1.set)
        scrollbar1.pack(side="right", fill="y")
        text_tree.pack(fill="both", expand=True)
        
        # File History Tab
        file_tab = tk.Frame(notebook)
        notebook.add(file_tab, text="File/Folder Encryption History")
        
        file_tree = ttk.Treeview(file_tab, columns=("Type", "Name", "Hash", "Timestamp"), show="headings")
        file_tree.heading("Type", text="Type")
        file_tree.heading("Name", text="Name")
        file_tree.heading("Hash", text="Password Hash")
        file_tree.heading("Timestamp", text="Timestamp")
        file_tree.column("Type", width=80)
        file_tree.column("Name", width=250)
        file_tree.column("Hash", width=250)
        file_tree.column("Timestamp", width=180)
        
        scrollbar2 = ttk.Scrollbar(file_tab, orient="vertical", command=file_tree.yview)
        file_tree.configure(yscrollcommand=scrollbar2.set)
        scrollbar2.pack(side="right", fill="y")
        file_tree.pack(fill="both", expand=True)
        
        # Load data
        for entry in get_all_text_entries():
            text_tree.insert("", "end", values=(entry.get("msg_id", ""), 
                                                 entry.get("password_hash", ""),
                                                 entry.get("timestamp", "")))
        
        for entry in get_all_file_entries():
            file_tree.insert("", "end", values=(entry.get("type", ""),
                                                 entry.get("name", ""),
                                                 entry.get("password_hash", ""),
                                                 entry.get("timestamp", "")))

    # ==================================================
    # TECHNOLOGIES WINDOW
    # ==================================================
    def show_technologies(self):
        window = tk.Toplevel(self.root)
        window.title("2026 Technologies")
        
        # Responsive sizing for technologies window
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = min(int(screen_width * 0.7), 900)
        window_height = min(int(screen_height * 0.7), 700)
        window_width = max(window_width, 600)
        window_height = max(window_height, 500)
        
        x_pos = (screen_width - window_width) // 2
        y_pos = (screen_height - window_height) // 2
        
        window.geometry(f"{window_width}x{window_height}+{x_pos}+{y_pos}")
        window.minsize(600, 500)
        window.maxsize(1100, 700)
        
        ttk.Label(window, text="💻 2026 Technology Stack",
                  font=("Segoe UI", 20, "bold")).pack(pady=10)
        
        canvas = tk.Canvas(window)
        scrollbar = ttk.Scrollbar(window, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas)
        
        scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        colors = ["#E3F2FD", "#E8F5E9", "#FFF3E0", "#FCE4EC", "#F3E5F5", "#E0F7FA"]
        
       

# ==================================================
# RUN
# ==================================================
if __name__ == "__main__":
    root = tk.Tk()
    SecureCryptoGUI(root)
    root.mainloop()
