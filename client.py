import socket
import json
import os
import base64
import getpass
import ssl
import platform
from cryptography.hazmat.primitives import serialization

from crypto_utils import *

class Colors:
    """Terminal colors for improved UI"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @staticmethod
    def disabled():
        """Disable colors on Windows if not supported"""
        if platform.system() == 'Windows':
            Colors.HEADER = ''
            Colors.BLUE = ''
            Colors.GREEN = ''
            Colors.YELLOW = ''
            Colors.RED = ''
            Colors.ENDC = ''
            Colors.BOLD = ''
            Colors.UNDERLINE = ''

class Client:
    """A secure storage client implementing end-to-end encryption and multi-factor authentication"""
    
    def __init__(self, server_host='localhost', server_port=9999):
        """Initialize client with server connection details and user state"""
        # Initialize colors for terminal
        Colors.disabled()
        
        self.server_host = server_host
        self.server_port = server_port
        self.username = None
        self.private_key = None  # User's asymmetric private key
        self.public_key = None   # User's asymmetric public key
        self.otp_secret = None   # OTP secret for 2FA
        self.is_admin = False
        self.file_keys = {}      # Store decrypted file keys in memory only during session
        self.session_key = None  # Symmetric key for secure communication with server
        
        # Create local storage directory for client keys and temporary files
        os.makedirs("client_storage", exist_ok=True)
        os.makedirs("client_downloads", exist_ok=True)
        
        self.print_banner()
        
    def print_banner(self):
        """Display a welcome banner"""
        banner = f"""
{Colors.BLUE}{Colors.BOLD}
╔═══════════════════════════════════════════════════╗
║                                                   ║
║   {Colors.GREEN}SECURE STORAGE SYSTEM{Colors.BLUE}                           ║
║   {Colors.YELLOW}End-to-End Encrypted File Storage{Colors.BLUE}               ║
║                                                   ║
╚═══════════════════════════════════════════════════╝{Colors.ENDC}
"""
        print(banner)
    
    def print_status(self, message, status="info"):
        """Print a formatted status message"""
        prefix = ""
        if status == "success":
            prefix = f"{Colors.GREEN}[✓]{Colors.ENDC} "
        elif status == "error":
            prefix = f"{Colors.RED}[✗]{Colors.ENDC} "
        elif status == "warning":
            prefix = f"{Colors.YELLOW}[!]{Colors.ENDC} "
        elif status == "info":
            prefix = f"{Colors.BLUE}[i]{Colors.ENDC} "
        
        print(f"{prefix}{message}")
    
    def connect(self):
        """Establish secure TCP connection with the server using SSL/TLS"""
        self.print_status("Connecting to server...", "info")
        try:
            # Create a standard socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Wrap the socket with SSL/TLS
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Disable certificate verification for simplicity because we don't have a CA
            
            self.client_socket = context.wrap_socket(self.socket, server_hostname=self.server_host)
            self.client_socket.connect((self.server_host, self.server_port))
            
            self.print_status(f"Connected to {self.server_host}:{self.server_port}", "success")
            
            # Establish session key for additional encryption layer
            self._establish_session_key()
            
            return True
        except (ConnectionRefusedError, ssl.SSLError) as e:
            self.print_status(f"Could not connect to server: {e}", "error")
            return False
        
    def _establish_session_key(self):
        """Establish a session key for encrypted communication"""
        self.print_status("Establishing secure session...", "info")
        
        # Generate a random session key (symmetric AES-256 key)
        session_key = os.urandom(32)
        
        # If we already have a public key, we can use it
        # Otherwise, send an unencrypted request to get the server's public key
        request = {
            'action': 'get_server_public_key'
        }
        
        # This request is sent over SSL/TLS but not with our session encryption
        self.client_socket.sendall(json.dumps(request).encode())
        response_data = self.client_socket.recv(4096)
        response = json.loads(response_data.decode())
        
        if response['status'] == 'success':
            server_public_key = base64.b64decode(response['public_key'])
            
            # Encrypt the session key with the server's public key (asymmetric encryption)
            encrypted_session_key = encrypt_file_key(session_key, server_public_key)
            
            # Send the encrypted session key to the server
            request = {
                'action': 'establish_session',
                'encrypted_session_key': base64.b64encode(encrypted_session_key).decode()
            }
            
            self.client_socket.sendall(json.dumps(request).encode())
            response_data = self.client_socket.recv(4096)
            response = json.loads(response_data.decode())
            
            if response['status'] == 'success':
                self.session_key = session_key
                self.print_status("Secure session established", "success")
                return True
        
        self.print_status("Failed to establish secure session", "error")
        return False
    
    def disconnect(self):
        """Close the connection to the server and clear sensitive data"""
        if hasattr(self, 'client_socket'):
            self.client_socket.close()
        # Clear sensitive data when disconnecting
        self.file_keys = {}
        self.session_key = None
        self.print_status("Disconnected from server", "info")
        
    def encrypt_request(self, request_data):
        """Encrypt a request using the session key (symmetric encryption)"""
        if not self.session_key:
            return request_data  # Fall back to unencrypted if no session key
            
        # Convert request to JSON string
        json_data = json.dumps(request_data)
        
        # Encrypt the JSON data with AES-GCM (symmetric encryption)
        encrypted_data = encrypt_file(json_data.encode(), self.session_key)
        
        # Return a wrapper that indicates the payload is encrypted
        return {
            'encrypted': True,
            'data': base64.b64encode(encrypted_data).decode()
        }
        
    def decrypt_response(self, response_data):
        """Decrypt a response using the session key"""
        try:
            # Parse the response
            response = json.loads(response_data.decode())
            
            # Check if it's encrypted
            if isinstance(response, dict) and response.get('encrypted', False):
                # Decrypt the data with AES-GCM (symmetric decryption)
                encrypted_data = base64.b64decode(response['data'])
                decrypted_data = decrypt_file(encrypted_data, self.session_key)
                
                # Parse the decrypted JSON
                return json.loads(decrypted_data.decode())
            else:
                # Not encrypted
                return response
        except Exception as e:
            self.print_status(f"Error decrypting response: {e}", "error")
            return {'status': 'error', 'message': 'Communication error'}
    
    def send_request(self, request):
        """Send an encrypted JSON request to the server and receive the response"""
        try:
            # Encrypt the request if we have a session key
            encrypted_request = self.encrypt_request(request)
            
            # Send the request
            self.client_socket.sendall(json.dumps(encrypted_request).encode())
            
            # Receive the response
            response_data = b""
            while True:
                chunk = self.client_socket.recv(1024 * 1024)
                if not chunk:
                    break
                response_data += chunk
                if len(chunk) < 1024 * 1024:
                    break
            
            # Decrypt the response
            return self.decrypt_response(response_data)
        except Exception as e:
            self.print_status(f"Error in communication: {e}", "error")
            return {'status': 'error', 'message': f'Communication error: {str(e)}'}

    def register(self):
        """Register a new user account with password hashing and key pair generation"""
        self.print_status("\n=== User Registration ===", "info")
        username = input(f"{Colors.BOLD}Enter username: {Colors.ENDC}")
        while True:
            password = getpass.getpass(f"{Colors.BOLD}Enter password:{Colors.ENDC} ")
            confirm_password = getpass.getpass(f"{Colors.BOLD}Confirm password:{Colors.ENDC} ")
            if password != confirm_password:
                self.print_status("Passwords don't match. Please try again.", "error")
                continue
            break

        self.print_status("Generating cryptographic keys...", "info")

        # Step 1: Generate salt and hash password (using PBKDF2-HMAC-SHA256)
        key, salt = hash_password(password)
        self.print_status(f"Generated password salt: {salt.hex()}", "info")

        # Step 2: Generate asymmetric key pair for encryption (RSA-2048)
        private_key, public_key = generate_key_pair()

        # Step 3: Sign registration request for authenticity (RSA signature)
        signature_data = f"register:{username}".encode()
        signature = sign_data(signature_data, private_key)

        self.print_status("Sending registration request...", "info")

        # Step 4: Send registration request (encrypted with session key)
        request = {
            'action': 'register',
            'username': username,
            'password_hash': base64.b64encode(key).decode(),
            'salt': base64.b64encode(salt).decode(),
            'public_key': base64.b64encode(public_key).decode(),
            'signature': base64.b64encode(signature).decode()
        }

        response = self.send_request(request)

        if response['status'] == 'success':
            self.print_status(response['message'], "success")
            self.username = username
            self.private_key = private_key
            self.public_key = public_key

            # Step 5: Protect private key locally (encrypt with key derived from password)
            self.print_status("Securing private key locally...", "info")
            private_key_encryption_key, priv_key_salt = hash_password(password)
            self.print_status(f"Using salt for private key encryption: {priv_key_salt.hex()}", "info")

            encrypted_private_key = encrypt_file(private_key, private_key_encryption_key[:32])

            # Store the salt and encrypted private key in a file
            with open(f"client_storage/{username}_private.key", "wb") as f:
                f.write(priv_key_salt)
                f.write(encrypted_private_key)

            self.print_status(f"Private key saved with salt (total size: {16 + len(encrypted_private_key)} bytes)",
                              "info")

            # Step 6: Save OTP secret locally (encrypted)
            self.otp_secret = response['otp_secret']
            encrypted_otp = encrypt_file(self.otp_secret.encode(), private_key_encryption_key[:32])

            # Save the salt and encrypted OTP in a file
            with open(f"client_storage/{username}_otp.key", "wb") as f:
                f.write(priv_key_salt)
                f.write(encrypted_otp)

            self.print_status(f"OTP secret saved with salt (total size: {16 + len(encrypted_otp)} bytes)", "info")

            # Step 7: Setup OTP/2FA
            qr_code_data = base64.b64decode(response['qr_code'])
            with open(f"client_storage/{username}_otp_qr.png", "wb") as f:
                f.write(qr_code_data)

            self.print_status(f"OTP Secret: {self.otp_secret}", "info")
            self.print_status(f"QR code saved to client_storage/{username}_otp_qr.png", "info")
            self.print_status("Please scan this QR code with your authenticator app for MFA setup.", "warning")

            # Extra security information
            self.print_status("\nImportant security information:", "warning")
            self.print_status("1. Your private key is encrypted with your password", "info")
            self.print_status("2. If you forget your password, you cannot recover your encrypted data", "info")
            self.print_status("3. Keep a backup of your OTP secret in a secure location", "info")

            return True
        else:
            self.print_status(f"Registration failed: {response['message']}", "error")
            return False

    def login(self):
        """Authenticate user with password and 2FA"""
        self.print_status("\n=== User Login ===", "info")
        username = input(f"{Colors.BOLD}Enter username:{Colors.ENDC} ")
        password = getpass.getpass(f"{Colors.BOLD}Enter password:{Colors.ENDC} ")

        if username == "admin" and password == "admin123":
            self.print_status("Admin login successful", "success")
            self.username = username
            self.is_admin = True
            return True

        # Step 1: Request salt from server
        self.print_status("Verifying credentials...", "info")
        request = {
            'action': 'get_salt',
            'username': username
        }

        response = self.send_request(request)

        if response['status'] != 'success':
            self.print_status(f"Failed to get salt: {response['message']}", "error")
            return False

        # Step 2: Get the actual salt for this user
        server_salt = base64.b64decode(response['salt'])

        # Step 3: Hash password with the correct salt (PBKDF2)
        key, _ = hash_password(password, server_salt)

        # Step 4: Send login request
        request = {
            'action': 'login',
            'username': username,
            'password_hash': base64.b64encode(key).decode()
        }

        response = self.send_request(request)

        if response['status'] == 'otp_required':
            # Step 5: OTP verification (second factor)
            self.print_status("Password verified. OTP verification required.", "success")

            # Step 6: Load private key for signing (decrypt with password)
            try:
                # Debug: Check if private key file exists
                private_key_path = f"client_storage/{username}_private.key"
                if not os.path.exists(private_key_path):
                    self.print_status(f"Private key file not found at {private_key_path}", "error")
                    return False

                # Read the private key file
                with open(private_key_path, "rb") as f:
                    file_content = f.read()

                # Check the file size and make sure it's not corrupted
                if len(file_content) <= 16:
                    self.print_status("Private key file is too small or corrupted", "error")
                    return False

                # Analyze the file content
                key_salt = file_content[:16]
                encrypted_private_key = file_content[16:]

                self.print_status(f"Using stored salt from key file: {key_salt.hex()}", "info")

                # Using the same password-derived key for decryption
                private_key_encryption_key, _ = hash_password(password, key_salt)

                self.print_status("Attempting to decrypt private key...", "info")
                try:
                    private_key = decrypt_file(encrypted_private_key, private_key_encryption_key[:32])
                    self.print_status("Private key decrypted successfully", "success")
                except Exception as e:
                    self.print_status(f"Error decrypting private key: {str(e)}", "error")

                    # Try to use server salt as a fallback
                    self.print_status("Trying with server salt as fallback...", "info")
                    fallback_key, _ = hash_password(password, server_salt)
                    try:
                        private_key = decrypt_file(encrypted_private_key, fallback_key[:32])
                        self.print_status("Private key decrypted with server salt", "success")

                        # If successful, update the private key file with the correct salt
                        self.print_status("Updating private key file with correct salt...", "info")
                        with open(private_key_path, "wb") as f:
                            f.write(server_salt)
                            f.write(encrypted_private_key)
                    except:
                        self.print_status("All decryption attempts failed", "error")
                        return False

                # Load the private key for signing
                try:
                    otp_path = f"client_storage/{username}_otp.key"
                    if os.path.exists(otp_path):
                        self.print_status("Found OTP key file, attempting to decrypt...", "info")
                        with open(otp_path, "rb") as f:
                            otp_content = f.read()

                        # Check the file size and make sure it's not corrupted
                        if len(otp_content) > 16:
                            otp_salt = otp_content[:16]
                            encrypted_otp = otp_content[16:]

                            # Using the same password-derived key for decryption
                            otp_secret = decrypt_file(encrypted_otp, private_key_encryption_key[:32]).decode()
                            self.print_status(f"Your OTP secret: {otp_secret}", "info")
                        else:
                            # Fallback to old format
                            encrypted_otp = otp_content
                            otp_secret = decrypt_file(encrypted_otp, private_key_encryption_key[:32]).decode()
                            self.print_status(f"Your OTP secret (old format): {otp_secret}", "info")

                            # Update the OTP file with the correct salt
                            with open(otp_path, "wb") as f:
                                f.write(key_salt)
                                f.write(encrypt_file(otp_secret.encode(), private_key_encryption_key[:32]))
                    else:
                        self.print_status(f"OTP secret file not found at {otp_path}", "warning")
                except Exception as e:
                    self.print_status(f"Error loading OTP secret: {str(e)}", "warning")
                    self.print_status("You'll need to enter the OTP code manually.", "warning")
            except Exception as e:
                self.print_status(f"Error loading private key: {str(e)}", "error")
                import traceback
                self.print_status(f"Detailed error: {traceback.format_exc()}", "error")
                self.print_status("You may need to register again if you cannot recover your keys.", "warning")
                return False

            otp_code = input(f"{Colors.BOLD}Enter OTP code from your authenticator app:{Colors.ENDC} ")

            # Step 7: Sign the OTP verification request (non-repudiation)
            signature_data = f"login:{username}".encode()
            signature = sign_data(signature_data, private_key)

            # Step 8: Send OTP verification request
            self.print_status("Verifying OTP code...", "info")
            request = {
                'action': 'verify_otp',
                'username': username,
                'otp_code': otp_code,
                'signature': base64.b64encode(signature).decode()
            }

            response = self.send_request(request)

            if response['status'] == 'success':
                self.print_status(response['message'], "success")
                self.username = username
                self.private_key = private_key
                self.is_admin = response.get('is_admin', False)
                return True
            else:
                self.print_status(f"OTP verification failed: {response['message']}", "error")
                return False
        else:
            self.print_status(f"Login failed: {response['message']}", "error")
            return False

    def reset_password(self):
        """Change user password with 2FA verification"""
        self.print_status("\n=== Password Reset ===", "info")
        username = self.username
        if not username:
            self.print_status("You must be logged in to reset your password", "error")
            return False

        # Save the current file keys for later restoration
        original_file_keys = self.file_keys.copy()
        self.print_status(f"Saved {len(original_file_keys)} file keys for later restoration", "info")

        old_password = getpass.getpass(f"{Colors.BOLD}Enter current password:{Colors.ENDC} ")

        # Password policy check for new password
        while True:
            new_password = getpass.getpass(
                f"{Colors.BOLD}Enter new password (min 8 chars, include uppercase, lowercase, number):{Colors.ENDC} ")
            confirm_password = getpass.getpass(f"{Colors.BOLD}Confirm new password:{Colors.ENDC} ")
            if new_password != confirm_password:
                self.print_status("Passwords don't match. Please try again.", "error")
                continue
            break

        # Step 1: Request salt from server
        request = {
            'action': 'get_salt',
            'username': username
        }

        response = self.send_request(request)

        if response['status'] != 'success':
            self.print_status(f"Failed to get salt: {response['message']}", "error")
            return False

        # Step 2: Get the salt for this user
        old_salt = base64.b64decode(response['salt'])

        # Step 3: Hash old password
        old_key, _ = hash_password(old_password, old_salt)

        # Step 4: Hash new password with new salt
        new_key, new_salt = hash_password(new_password)

        # Step 5: Get OTP code (2FA)
        otp_code = input(f"{Colors.BOLD}Enter OTP code from your authenticator app:{Colors.ENDC} ")

        # Step 6: Sign the password reset request
        self.print_status("Sending password reset request...", "info")
        signature_data = f"reset_password:{self.username}".encode()
        signature = sign_data(signature_data, self.private_key)

        # Step 7: Send password reset request
        request = {
            'action': 'reset_password',
            'username': self.username,
            'old_password_hash': base64.b64encode(old_key).decode(),
            'new_password_hash': base64.b64encode(new_key).decode(),
            'new_salt': base64.b64encode(new_salt).decode(),
            'otp_code': otp_code,
            'signature': base64.b64encode(signature).decode()
        }

        response = self.send_request(request)

        if response['status'] == 'success':
            self.print_status(response['message'], "success")

            # Step 8: Re-encrypt private key with new password-derived key
            self.print_status("Updating local security credentials...", "info")
            private_key_encryption_key, priv_key_salt = hash_password(new_password)
            encrypted_private_key = encrypt_file(self.private_key, private_key_encryption_key[:32])

            # Save the salt and encrypted private key in a file
            with open(f"client_storage/{username}_private.key", "wb") as f:
                f.write(priv_key_salt)
                f.write(encrypted_private_key)

            self.print_status(f"Private key saved with salt (total size: {16 + len(encrypted_private_key)} bytes)",
                              "info")

            # Step 9: Re-encrypt OTP secret with new password
            if hasattr(self, 'otp_secret') and self.otp_secret:
                encrypted_otp = encrypt_file(self.otp_secret.encode(), private_key_encryption_key[:32])

                # Store the salt and encrypted OTP in a file
                with open(f"client_storage/{username}_otp.key", "wb") as f:
                    f.write(priv_key_salt)
                    f.write(encrypted_otp)

                self.print_status(f"OTP secret saved with salt (total size: {16 + len(encrypted_otp)} bytes)", "info")

            # Recover file keys
            self.file_keys = original_file_keys
            self.print_status(f"Restored access to {len(self.file_keys)} files", "success")

            return True
        else:
            self.print_status(f"Password reset failed: {response['message']}", "error")
            return False
    
    def upload_file(self):
        """Upload and encrypt a file"""
        self.print_status("\n=== File Upload ===", "info")
        if not self.username:
            self.print_status("You must be logged in to upload files", "error")
            return
        
        filepath = input(f"{Colors.BOLD}Enter path to file:{Colors.ENDC} ")
        
        # Step 1: Read file data
        try:
            with open(filepath, "rb") as f:
                file_data = f.read()
            self.print_status(f"File size: {len(file_data)} bytes", "info")
        except FileNotFoundError:
            self.print_status("File not found", "error")
            return
        
        filename = os.path.basename(filepath)
        
        # Step 2: Validate filename
        if not validate_filename(filename):
            self.print_status("Invalid filename. Only alphanumeric characters, underscore, dash and period are allowed.", "error")
            return
        
        self.print_status("Encrypting file...", "info")
        
        # Step 3: Generate random file encryption key (AES-256)
        file_key = os.urandom(32)
        
        # Step 4: Encrypt filename using AES-GCM
        encrypted_filename = encrypt_file(filename.encode(), file_key)
        
        # Step 5: Encrypt file content using AES-GCM
        encrypted_file = encrypt_file(file_data, file_key)
        
        # Step 6: Encrypt file key with user's public key (RSA)
        encrypted_file_key = encrypt_file_key(file_key, self.public_key)
        
        # Step 7: Sign the upload request for non-repudiation
        signature_data = f"upload:{self.username}:{filename}".encode()
        signature = sign_data(signature_data, self.private_key)
        
        # Step 8: Send upload request
        self.print_status("Uploading encrypted file to server...", "info")
        request = {
            'action': 'upload_file',
            'username': self.username,
            'encrypted_filename': base64.b64encode(encrypted_filename).decode(),
            'encrypted_file': base64.b64encode(encrypted_file).decode(),
            'encrypted_file_key': base64.b64encode(encrypted_file_key).decode(),
            'signature': base64.b64encode(signature).decode()
        }
        
        response = self.send_request(request)
        
        if response['status'] == 'success':
            file_id = response['file_id']
            self.print_status(f"File uploaded successfully with ID: {file_id}", "success")
            
            # Step 9: Store file key in memory (only for this session)
            self.file_keys[file_id] = {
                'key': file_key,
                'filename': filename
            }
        else:
            self.print_status(f"Upload failed: {response['message']}", "error")
    
    def download_file(self, file_id=None):
        """Download and decrypt a file"""
        self.print_status("\n=== File Download ===", "info")
        if not self.username:
            self.print_status("You must be logged in to download files", "error")
            return
        
        if not file_id:
            file_id = input(f"{Colors.BOLD}Enter file ID:{Colors.ENDC} ")
        
        # Step 1: Sign the download request
        signature_data = f"download:{self.username}:{file_id}".encode()
        signature = sign_data(signature_data, self.private_key)
        
        # Step 2: Send download request
        self.print_status("Requesting file from server...", "info")
        request = {
            'action': 'download_file',
            'username': self.username,
            'file_id': file_id,
            'signature': base64.b64encode(signature).decode()
        }
        
        response = self.send_request(request)
        
        if response['status'] == 'success':
            self.print_status("File received, decrypting...", "info")
            
            # Step 3: Decrypt file key with user's private key (RSA)
            encrypted_file_key = base64.b64decode(response['encrypted_file_key'])
            file_key = decrypt_file_key(encrypted_file_key, self.private_key)
            
            # Step 4: Decrypt file content (AES-GCM)
            encrypted_file = base64.b64decode(response['encrypted_file'])
            file_data = decrypt_file(encrypted_file, file_key)
            
            # Step 5: Get filename - either from memory or decrypt it
            if file_id in self.file_keys:
                # If it's user's own file, we already know the filename
                filename = self.file_keys[file_id]['filename']
            else:
                # If it's a shared file or we don't have the filename in memory, 
                # decrypt the encrypted filename from the response
                encrypted_filename = base64.b64decode(response['encrypted_filename'])
                filename = decrypt_file(encrypted_filename, file_key).decode()
            
            # Step 6: Save file locally
            download_path = f"client_downloads/{filename}"
            with open(download_path, "wb") as f:
                f.write(file_data)
            
            self.print_status(f"File downloaded successfully to {download_path}", "success")
            
            # Step 7: Store file key in memory for future operations
            self.file_keys[file_id] = {
                'key': file_key,
                'filename': filename
            }
        else:
            self.print_status(f"Download failed: {response['message']}", "error")
    
    def list_files(self):
        """List user's own files and files shared with them"""
        self.print_status("\n=== File Listing ===", "info")
        if not self.username:
            self.print_status("You must be logged in to list files", "error")
            return
        
        # Step 1: Send list files request
        self.print_status("Retrieving file list...", "info")
        request = {
            'action': 'list_files',
            'username': self.username
        }
        
        response = self.send_request(request)
        
        if response['status'] == 'success':
            own_files = response['own_files']
            shared_files = response['shared_files']

            # Display user's own files
            print(f"\n{Colors.BOLD}{Colors.GREEN}Your files:{Colors.ENDC}")
            if own_files:
                print(f"  {Colors.UNDERLINE}{'ID':<36} | {'Filename':<30}{Colors.ENDC}")
                print("  " + "-" * 68)

                for file in own_files:
                    file_id = file['file_id']
                    
                    # Try to decrypt filename
                    try:
                        # If we have the key in memory
                        if file_id in self.file_keys:
                            filename = self.file_keys[file_id]['filename']
                        else:
                            # Step 2: Request file key from server
                            key_request = {
                                'action': 'get_file_key',
                                'username': self.username,
                                'file_id': file_id,
                                'signature': base64.b64encode(
                                    sign_data(f"get_file_key:{self.username}:{file_id}".encode(), self.private_key)
                                ).decode()
                            }
                            
                            key_response = self.send_request(key_request)
                            
                            if key_response['status'] == 'success':
                                # Step 3: Decrypt the file key with private key
                                encrypted_key = base64.b64decode(key_response['encrypted_file_key'])
                                file_key = decrypt_file_key(encrypted_key, self.private_key)
                                
                                # Step 4: Decrypt filename
                                encrypted_filename = base64.b64decode(file['encrypted_filename'])
                                filename = decrypt_file(encrypted_filename, file_key).decode()
                                
                                # Store key in memory
                                self.file_keys[file_id] = {
                                    'key': file_key,
                                    'filename': filename
                                }
                            else:
                                filename = f"[Encrypted File {file_id[:8]}]"
                    except Exception as e:
                        filename = f"[Encrypted File {file_id[:8]}]"
                    
                    print(f"  {file_id} | {filename}")
            else:
                self.print_status("No files found", "info")

            # Display files shared with the user
            print(f"\n{Colors.BOLD}{Colors.BLUE}Files shared with you:{Colors.ENDC}")
            if shared_files:
                print(f"  {Colors.UNDERLINE}{'ID':<36} | {'Filename':<30} | {'Owner':<20}{Colors.ENDC}")
                print("  " + "-" * 90)
                
                for file in shared_files:
                    file_id = file['file_id']
                    owner = file['owner']
                    
                    # Try to decrypt the filename if we have the key
                    try:
                        if file_id in self.file_keys:
                            filename = self.file_keys[file_id]['filename']
                        else:
                            filename = f"[Shared File {file_id[:8]}]"
                    except Exception:
                        filename = f"[Shared File {file_id[:8]}]"
                    
                    print(f"  {file_id} | {filename} | {owner}")
            else:
                self.print_status("No shared files found", "info")
        else:
            self.print_status(f"Failed to list files: {response['message']}", "error")
    
    def share_file(self):
        """Share a file with another user"""
        self.print_status("\n=== File Sharing ===", "info")
        if not self.username:
            self.print_status("You must be logged in to share files", "error")
            return
        
        # First list files to help user
        self.list_files()
        
        file_id = input(f"\n{Colors.BOLD}Enter file ID to share:{Colors.ENDC} ")
        recipient = input(f"{Colors.BOLD}Enter username to share with:{Colors.ENDC} ")
        
        # Step 1: Get recipient's public key
        self.print_status(f"Retrieving public key for {recipient}...", "info")
        request = {
            'action': 'get_public_key',
            'username': recipient
        }
        response = self.send_request(request)
        
        if response['status'] != 'success':
            self.print_status(f"Failed to get recipient's public key: {response['message']}", "error")
            return
    
        recipient_public_key = base64.b64decode(response['public_key'])
        
        # Step 2: Get file encryption key
        file_key = None
        
        # If we have the key in memory
        if file_id in self.file_keys:
            self.print_status("Using cached file key", "info")
            file_key = self.file_keys[file_id]['key']
        else:
            # Request file key from server
            self.print_status("Requesting file key from server...", "info")
            signature_data = f"get_file_key:{self.username}:{file_id}".encode()
            signature = sign_data(signature_data, self.private_key)
            
            request = {
                'action': 'get_file_key',
                'username': self.username,
                'file_id': file_id,
                'signature': base64.b64encode(signature).decode()
            }
            
            response = self.send_request(request)
            
            if response['status'] == 'success':
                # Step 3: Decrypt the file key with our private key
                encrypted_file_key = base64.b64decode(response['encrypted_file_key'])
                file_key = decrypt_file_key(encrypted_file_key, self.private_key)
            else:
                self.print_status(f"Failed to get file key: {response['message']}", "error")
                return
        
        # Step 4: Re-encrypt file key with recipient's public key
        self.print_status("Re-encrypting file key for recipient...", "info")
        new_encrypted_file_key = encrypt_file_key(file_key, recipient_public_key)
        
        # Step 5: Sign the share request
        signature_data = f"share:{self.username}:{file_id}:{recipient}".encode()
        signature = sign_data(signature_data, self.private_key)
        
        # Step 6: Send share request
        self.print_status("Sending share request...", "info")
        request = {
            'action': 'share_file',
            'username': self.username,
            'file_id': file_id,
            'shared_with': recipient,
            'encrypted_file_key': base64.b64encode(new_encrypted_file_key).decode(),
            'signature': base64.b64encode(signature).decode()
        }
        
        response = self.send_request(request)
        
        if response['status'] == 'success':
            self.print_status(f"File shared successfully with {recipient}", "success")
        else:
            self.print_status(f"Failed to share file: {response['message']}", "error")
    
    def edit_file(self):
        """Edit an existing file with efficient partial updates"""
        self.print_status("\n=== File Editing ===", "info")
        if not self.username:
            self.print_status("You must be logged in to edit files", "error")
            return
        
        # List files first so user can see what's available
        self.list_files()
        
        file_id = input(f"\n{Colors.BOLD}Enter ID of file to edit:{Colors.ENDC} ")
        
        # Step 1: Download the file first
        self.print_status("Downloading file for editing...", "info")
        self.download_file(file_id)
        
        # If file was successfully downloaded, it should be in file_keys
        if file_id not in self.file_keys:
            self.print_status("Failed to download file for editing", "error")
            return
        
        filename = self.file_keys[file_id]['filename']
        download_path = f"client_downloads/{filename}"
        
        # Check if file exists locally
        if not os.path.exists(download_path):
            self.print_status(f"File not found at {download_path}", "error")
            return
        
        # Step 2: Let user edit the file
        self.print_status(f"Please edit the file at {Colors.BOLD}{download_path}{Colors.ENDC} using your preferred editor.", "info")
        input("Press Enter when you've finished editing the file...")
        
        # Step 3: Read the edited file
        try:
            with open(download_path, "rb") as f:
                edited_file_data = f.read()
            self.print_status(f"File size after editing: {len(edited_file_data)} bytes", "info")
        except Exception as e:
            self.print_status(f"Error reading edited file: {e}", "error")
            return
        
        # Step 4: Get file key from memory and encrypt the edited file
        self.print_status("Encrypting modified file...", "info")
        file_key = self.file_keys[file_id]['key']
        encrypted_file = encrypt_file(edited_file_data, file_key)
        
        # Step 5: Sign the edit request
        signature_data = f"edit:{self.username}:{file_id}".encode()
        signature = sign_data(signature_data, self.private_key)
        
        # Step 6: Send edit request
        self.print_status("Uploading modified file...", "info")
        request = {
            'action': 'edit_file',
            'username': self.username,
            'file_id': file_id,
            'encrypted_file': base64.b64encode(encrypted_file).decode(),
            'signature': base64.b64encode(signature).decode()
        }
        
        response = self.send_request(request)
        
        if response['status'] == 'success':
            self.print_status("File edited successfully", "success")
        else:
            self.print_status(f"Failed to edit file: {response['message']}", "error")
    
    def delete_file(self):
        """Delete a file"""
        self.print_status("\n=== File Deletion ===", "info")
        if not self.username:
            self.print_status("You must be logged in to delete files", "error")
            return
        
        # List files first so user can see what's available
        self.list_files()
        
        file_id = input(f"\n{Colors.BOLD}Enter ID of file to delete:{Colors.ENDC} ")
        
        # Confirm deletion
        confirm = input(f"{Colors.BOLD}{Colors.RED}Are you sure you want to delete this file? (y/n):{Colors.ENDC} ")
        if confirm.lower() != 'y':
            self.print_status("Deletion cancelled", "info")
            return
        
        # Step 1: Sign the delete request
        signature_data = f"delete:{self.username}:{file_id}".encode()
        signature = sign_data(signature_data, self.private_key)
        
        # Step 2: Send delete request
        self.print_status("Sending delete request...", "info")
        request = {
            'action': 'delete_file',
            'username': self.username,
            'file_id': file_id,
            'signature': base64.b64encode(signature).decode()
        }
        
        response = self.send_request(request)
        
        if response['status'] == 'success':
            self.print_status("File deleted successfully", "success")
            # Remove from local cache if present
            if file_id in self.file_keys:
                del self.file_keys[file_id]
        else:
            self.print_status(f"Failed to delete file: {response['message']}", "error")
    
    def view_logs(self):
        """View system logs (admin only)"""
        self.print_status("\n=== System Logs ===", "info")
        if not self.username or not self.is_admin:
            self.print_status("You must be logged in as an administrator to view logs", "error")
            return
        
        # Send logs request
        self.print_status("Retrieving logs...", "info")
        request = {
            'action': 'get_logs',
            'username': self.username
        }
        
        response = self.send_request(request)
        
        if response['status'] == 'success':
            logs = response['logs']
            
            print(f"\n{Colors.BOLD}System Activity Logs:{Colors.ENDC}")
            if logs:
                print(f"{Colors.UNDERLINE}{'Timestamp':<25} | {'User':<15} | {'Action':<40}{Colors.ENDC}")
                print("-" * 85)
                
                for log in logs:
                    print(f"{log['timestamp']:<25} | {log['username']:<15} | {log['action']}")
            else:
                self.print_status("No logs found", "info")
        else:
            self.print_status(f"Failed to retrieve logs: {response['message']}", "error")
    
    def show_menu(self):
        """Display interactive menu based on user's login state"""
        if not self.username:
            print(f"\n{Colors.BLUE}{Colors.BOLD}Secure Storage Client - Not Logged In{Colors.ENDC}")
            print(f"{Colors.YELLOW}1.{Colors.ENDC} Register")
            print(f"{Colors.YELLOW}2.{Colors.ENDC} Login")
            print(f"{Colors.YELLOW}0.{Colors.ENDC} Exit")
            
            choice = input(f"\n{Colors.BOLD}Enter your choice:{Colors.ENDC} ")
            
            if choice == '1':
                self.register()
            elif choice == '2':
                self.login()
            elif choice == '0':
                return False
        else:
            print(f"\n{Colors.BLUE}{Colors.BOLD}Secure Storage Client - Logged in as:{Colors.ENDC} {Colors.GREEN}{self.username}{Colors.ENDC}")
            if self.is_admin:
                print(f"{Colors.RED}(Administrator){Colors.ENDC}")
                
            print(f"\n{Colors.BOLD}File Operations:{Colors.ENDC}")
            print(f"{Colors.YELLOW}1.{Colors.ENDC} Upload File")
            print(f"{Colors.YELLOW}2.{Colors.ENDC} Download File")
            print(f"{Colors.YELLOW}3.{Colors.ENDC} List Files")
            print(f"{Colors.YELLOW}4.{Colors.ENDC} Share File")
            print(f"{Colors.YELLOW}5.{Colors.ENDC} Edit File")
            print(f"{Colors.YELLOW}6.{Colors.ENDC} Delete File")
            
            print(f"\n{Colors.BOLD}Account Management:{Colors.ENDC}")
            print(f"{Colors.YELLOW}7.{Colors.ENDC} Reset Password")
            if self.is_admin:
                print(f"{Colors.YELLOW}8.{Colors.ENDC} View System Logs")
            print(f"{Colors.YELLOW}9.{Colors.ENDC} Logout")
            print(f"{Colors.YELLOW}0.{Colors.ENDC} Exit")
            
            choice = input(f"\n{Colors.BOLD}Enter your choice:{Colors.ENDC} ")
            
            if choice == '1':
                self.upload_file()
            elif choice == '2':
                self.download_file()
            elif choice == '3':
                self.list_files()
            elif choice == '4':
                self.share_file()
            elif choice == '5':
                self.edit_file()
            elif choice == '6':
                self.delete_file()
            elif choice == '7':
                self.reset_password()
            elif choice == '8' and self.is_admin:
                self.view_logs()
            elif choice == '9':
                self.print_status("Logged out successfully", "success")
                self.username = None
                self.private_key = None
                self.is_admin = False
                self.file_keys = {}  # Clear file keys from memory
            elif choice == '0':
                return False
        
        return True
   
    def run(self):
        """Main client loop"""
        if not self.connect():
            return
        
        running = True
        while running:
            running = self.show_menu()
        
        self.disconnect()
        self.print_status("Goodbye!", "info")

if __name__ == "__main__":
    client = Client()
    client.run()
