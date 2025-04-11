import socket
import threading
import json
import base64
import uuid
import os
import time
import ssl
from datetime import datetime
from db_utils import *
from crypto_utils import *
from otp import OTP

class Server:
    """
    Secure Storage Server class implements encrypted file storage service with
    end-to-end encryption, multi-factor authentication, and secure communication.
    """
    
    def __init__(self, host='localhost', port=9999, use_ssl=True):
        """
        Initialize server with network settings and database
        
        Args:
            host (str): Server host address
            port (int): Server port number
            use_ssl (bool): Whether to use SSL/TLS for secure communication
        """
        # Server network configuration
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Banner display
        self._print_banner()
        
        # Initialize database
        self._log("[INFO] Initializing database...")
        init_db()
        self._log("[SUCCESS] Database initialized")

        # Track client sessions - mapping client addresses to session keys
        self.client_sessions = {}  # client_address -> session_key
        
        # Track failed login attempts for rate limiting
        self.failed_login_attempts = {}  # client_ip -> {count, timestamp}
        
        # Create admin account if it doesn't exist
        self._log("[INFO] Creating admin account...")
        self._create_admin_account()
        self._log("[SUCCESS] Admin account created or verified")
        
        # Generate server key pair for session key encryption
        self._log("[INFO] Generating server cryptographic keys...")
        self.server_private_key, self.server_public_key = generate_key_pair()
        self._log("[SUCCESS] Server keys generated")
        
        # Create storage directory for large files
        self._log("[INFO] Setting up file storage...")
        os.makedirs("file_storage", exist_ok=True)
        self._log("[SUCCESS] File storage ready")
        
        # Setup SSL context if enabled
        if use_ssl:
            self._log("[INFO] Configuring SSL/TLS...")
            self.context = self._create_ssl_context()
            self._log("[SUCCESS] SSL/TLS configured")
    
    def _print_banner(self):
        """Display server banner on startup"""
        banner = """
┌───────────────────────────────────────────────────────┐
│                                                       │
│   SECURE STORAGE SERVER                               │
│   End-to-End Encrypted File Storage                   │
│                                                       │
│   Version: 1.0                                        │
│   Implements: TLS, AES-GCM, RSA, PBKDF2, TOTP         │
│                                                       │
└───────────────────────────────────────────────────────┘
"""
        print(banner)
    
    def _log(self, message):
        """
        Log a message with timestamp
        
        Args:
            message (str): Message to log
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")
    
    def _create_admin_account(self):
        """
        Create admin account with username 'admin' and password 'admin123'
        if it doesn't already exist in the database, and create a communication session
        """
        from crypto_utils import hash_password, generate_key_pair
        import sqlite3
        import os
        
        conn = sqlite3.connect("server_storage.db")
        cursor = conn.cursor()
        
        # Check if admin account already exists
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        admin_exists = cursor.fetchone()
        
        admin_username = "admin"
        admin_password = "admin123"
        
        if not admin_exists:
            # Create admin account
            # Hash password
            key, salt = hash_password(admin_password)
            
            # Generate key pair
            private_key, public_key = generate_key_pair()
            
            # Store admin account in database
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt, public_key, is_admin) VALUES (?, ?, ?, ?, 1)",
                (admin_username, key, salt, public_key)
            )
            
            self._log(f"[INFO] Created new admin account with username '{admin_username}'")
            conn.commit()
        else:
            self._log("[INFO] Admin account already exists")
        
        conn.close()
        
        # Create a communication session for admin
        self._log("[INFO] Creating communication session for admin...")
        
        # Generate a session key for admin
        admin_session_key = os.urandom(32)
        
        # Store the session key (as if admin had logged in)
        # Using 'admin@localhost' as a placeholder for the client address
        admin_client_address = "admin@localhost"
        self.client_sessions[admin_client_address] = admin_session_key
        
        # Log action
        admin_signature = b''  # Empty signature as this is done by the server
        add_log(admin_username, "Admin automatic login via server initialization", admin_signature)
        
        self._log(f"[SUCCESS] Communication session created for admin at {admin_client_address}")
    
    def _create_ssl_context(self):
        """
        Create and configure SSL context for secure communications
        
        Returns:
            ssl.SSLContext: Configured SSL context
        """
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Generate self-signed certificates for development
        # In production, this should use proper CA-signed certificates
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        import datetime
        
        # Generate RSA key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Generate self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Secure Storage Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"securestorage.local"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(key, hashes.SHA256())
        
        # Save certificate and key
        with open("server.key", "wb") as f:
            f.write(key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))
        
        with open("server.crt", "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))
        
        # Load certificate and key
        context.load_cert_chain("server.crt", "server.key")
        return context
    
    def start(self):
        """Start the server and listen for client connections"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self._log(f"[SUCCESS] Server started on {self.host}:{self.port}")
        self._log("[INFO] Waiting for client connections...")
        
        try:
            while True:
                client_socket, address = self.server_socket.accept()
                
                # Wrap socket with SSL if enabled
                if self.use_ssl:
                    try:
                        client_socket = self.context.wrap_socket(client_socket, server_side=True)
                        self._log(f"[INFO] Secure connection established with {address[0]}:{address[1]}")
                    except ssl.SSLError as e:
                        self._log(f"[ERROR] SSL error with {address[0]}:{address[1]}: {e}")
                        client_socket.close()
                        continue
                else:
                    self._log(f"[WARNING] Unencrypted connection from {address[0]}:{address[1]}")
                
                # Create and start a new thread to handle this client
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address),
                    name=f"Client-{address[0]}:{address[1]}"
                )
                client_thread.daemon = True
                client_thread.start()
                self._log(f"[INFO] New client thread started for {address[0]}:{address[1]}")
                
        except KeyboardInterrupt:
            self._log("[INFO] Server shutting down due to keyboard interrupt...")
        except Exception as e:
            self._log(f"[ERROR] Unexpected server error: {e}")
        finally:
            self.server_socket.close()
            self._log("[INFO] Server socket closed")
            
    def decrypt_request(self, request_data, client_address):
        """
        Decrypt request if it's encrypted with a session key
        
        Args:
            request_data (bytes): Encrypted request data
            client_address (str): Client address identifier
            
        Returns:
            dict: Decrypted request as dictionary
        """
        try:
            # Parse the request
            request = json.loads(request_data.decode())
            
            # Check if it's encrypted with the session key
            if isinstance(request, dict) and request.get('encrypted', False):
                # Get session key for this client
                session_key = self.client_sessions.get(client_address)
                
                if not session_key:
                    return {'action': 'error', 'message': 'No session established'}
                
                # Decrypt the data with AES-GCM
                encrypted_data = base64.b64decode(request['data'])
                decrypted_data = decrypt_file(encrypted_data, session_key)
                
                # Parse the decrypted JSON
                return json.loads(decrypted_data.decode())
            else:
                # Not encrypted with session key (but still over SSL/TLS)
                return request
        except Exception as e:
            self._log(f"[ERROR] Failed to decrypt request from {client_address}: {e}")
            return {'action': 'error', 'message': 'Invalid request format'}
        
    def encrypt_response(self, response_data, client_address):
        """
        Encrypt response if a session key exists for this client
        
        Args:
            response_data (dict): Response data to encrypt
            client_address (str): Client address identifier
            
        Returns:
            dict: Encrypted or original response
        """
        # Get session key for this client
        session_key = self.client_sessions.get(client_address)
        
        if not session_key:
            return response_data
            
        # Convert response to JSON string
        json_data = json.dumps(response_data)
        
        # Encrypt the JSON data with AES-GCM
        encrypted_data = encrypt_file(json_data.encode(), session_key)
        
        # Return a wrapper that indicates the payload is encrypted
        encrypted_response = {
            'encrypted': True,
            'data': base64.b64encode(encrypted_data).decode()
        }
        
        return encrypted_response
    
    def handle_client(self, client_socket, address):
        """
        Handle client connection and process requests
        
        Args:
            client_socket (socket): Client socket connection
            address (tuple): Client address information (ip, port)
        """
        client_ip = address[0]
        client_port = address[1]
        client_address = f"{client_ip}:{client_port}"
        
        self._log(f"[INFO] Handling connection from {client_address}")
        
        try:
            while True:
                # Check if client is temporarily blocked due to too many failed login attempts
                # Skip rate limiting for trusted IPs
                if client_ip in self.failed_login_attempts:
                    failures = self.failed_login_attempts[client_ip]
                    if failures['count'] >= 5:
                        # If blocked and lockout period hasn't expired (30 seconds)
                        if time.time() - failures['timestamp'] < 30:
                            self._log(f"[WARNING] Rate limiting {client_address} - too many failed attempts")
                            response = {
                                'status': 'error', 
                                'message': 'Too many failed attempts. Try again later.'
                            }
                            client_socket.sendall(json.dumps(response).encode())
                            time.sleep(1)  # Prevent rapid retries
                            continue
                        else:
                            # Reset after lockout period
                            self._log(f"[INFO] Rate limit cleared for {client_address}")
                            del self.failed_login_attempts[client_ip]
                
                # Receive data from client
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        self._log(f"[INFO] Client {client_address} disconnected")
                        break
                    
                    # Decrypt request if it's encrypted
                    request = self.decrypt_request(data, client_address)
                    action = request.get('action')
                    
                    self._log(f"[INFO] Received action '{action}' from {client_address}")
                    
                    # Handle session establishment separately
                    if action == 'get_server_public_key':
                        self._log(f"[INFO] Providing server public key to {client_address}")
                        response = {
                            'status': 'success',
                            'public_key': base64.b64encode(self.server_public_key).decode()
                        }
                    elif action == 'establish_session':
                        response = self.handle_establish_session(request, client_address)
                    else:
                        # Process other request types
                        if action == 'get_salt':
                            response = self.handle_get_salt(request)
                        elif action == 'get_public_key':
                            response = self.handle_get_public_key(request)
                        elif action == 'get_file_key':
                            response = self.handle_get_file_key(request)
                        elif action == 'register':
                            response = self.handle_register(request)
                        elif action == 'login':
                            response = self.handle_login(request, client_ip)
                        elif action == 'verify_otp':
                            response = self.handle_verify_otp(request, client_ip)
                        elif action == 'reset_password':
                            response = self.handle_reset_password(request)
                        elif action == 'upload_file':
                            response = self.handle_upload_file(request)
                        elif action == 'download_file':
                            response = self.handle_download_file(request)
                        elif action == 'list_files':
                            response = self.handle_list_files(request)
                        elif action == 'share_file':
                            response = self.handle_share_file(request)
                        elif action == 'edit_file':
                            response = self.handle_edit_file(request)
                        elif action == 'delete_file':
                            response = self.handle_delete_file(request)
                        elif action == 'get_logs':
                            response = self.handle_get_logs(request)
                        else:
                            self._log(f"[WARNING] Unknown action '{action}' from {client_address}")
                            response = {'status': 'error', 'message': 'Unknown action'}
                
                except json.JSONDecodeError:
                    self._log(f"[ERROR] Invalid JSON received from {client_address}")
                    response = {'status': 'error', 'message': 'Invalid JSON format'}
                except ValueError as e:
                    self._log(f"[ERROR] Value error processing request from {client_address}: {e}")
                    response = {'status': 'error', 'message': f'Value error: {str(e)}'}
                except Exception as e:
                    self._log(f"[ERROR] Unexpected error processing request from {client_address}: {e}")
                    response = {'status': 'error', 'message': 'Server error'}
                
                # Encrypt response if session is established except for establishing session
                if action != 'establish_session':
                     # Encrypt response if session is established
                     response = self.encrypt_response(response, client_address)
                
                # Send response to client
                client_socket.sendall(json.dumps(response).encode())
                self._log(f"[INFO] Response sent to {client_address} (status: {response.get('status', 'unknown')})")
                
        except Exception as e:
            self._log(f"[ERROR] Error handling client {client_address}: {e}")
        finally:
            self._log(f"[INFO] Closing connection with {client_address}")
            # Clean up session if exists
            if client_address in self.client_sessions:
                del self.client_sessions[client_address]
                self._log(f"[INFO] Session cleared for {client_address}")
            client_socket.close()
    
    def handle_establish_session(self, request, client_address):
        """
        Handle session establishment request - decrypt the session key sent by client
        
        Args:
            request (dict): Client request containing encrypted session key
            client_address (str): Client address identifier
            
        Returns:
            dict: Response indicating success or failure
        """
        try:
            self._log(f"[INFO] Establishing secure session with {client_address}")
            encrypted_session_key = base64.b64decode(request.get('encrypted_session_key', ''))
            
            # Decrypt session key using server private key (RSA)
            session_key = decrypt_file_key(encrypted_session_key, self.server_private_key)
            
            # Store session key for this client
            self.client_sessions[client_address] = session_key
            self._log(f"[SUCCESS] Secure session established with {client_address}")
            
            return {'status': 'success', 'message': 'Session established'}
        except Exception as e:
            self._log(f"[ERROR] Failed to establish session with {client_address}: {e}")
            return {'status': 'error', 'message': 'Failed to establish session'}
    
    def handle_register(self, request):
        """
        Handle user registration - create new user with credentials
        
        Args:
            request (dict): Registration request with username, password hash, etc.
            
        Returns:
            dict: Response indicating success or failure
        """
        username = request.get('username')
        password_hash = base64.b64decode(request.get('password_hash'))
        salt = base64.b64decode(request.get('salt'))
        public_key = base64.b64decode(request.get('public_key'))
        
        self._log(f"[INFO] Processing registration for user '{username}'")
        
        # Generate OTP secret for MFA
        otp_secret = OTP.generate_secret()
        
        # Register user in the database
        if register_user(username, password_hash, salt, public_key, otp_secret):
            # Generate QR code for OTP setup
            qr_code = OTP.generate_qr_code(otp_secret, username)
            
            # Log the registration
            action = f"User registration successful"
            signature = base64.b64decode(request.get('signature', ''))
            add_log(username, action, signature)
            
            self._log(f"[SUCCESS] User '{username}' registered successfully")
            
            return {
                'status': 'success', 
                'message': 'User registered successfully',
                'otp_secret': otp_secret,
                'qr_code': base64.b64encode(qr_code).decode()
            }
        else:
            self._log(f"[ERROR] Registration failed - username '{username}' already exists")
            return {'status': 'error', 'message': 'Username already exists'}
    
    def handle_login(self, request, client_ip):
        """
        Handle initial login request - verify password
        
        Args:
            request (dict): Login request with username and password hash
            client_ip (str): Client IP address for rate limiting
            
        Returns:
            dict: Response indicating next authentication step or failure
        """
        username = request.get('username')
        password_hash = base64.b64decode(request.get('password_hash'))
        
        self._log(f"[INFO] Login attempt for user '{username}'")
        
        user = get_user(username)
        if not user:
            self._log(f"[WARNING] Login failed - user '{username}' not found")
            self._record_failed_attempt(client_ip)
            return {'status': 'error', 'message': 'Invalid credentials'}
        
        stored_hash = user[1]
        
        # Verify password hash
        if password_hash == stored_hash:
            self._log(f"[INFO] Password verified for '{username}', requesting OTP")
            # Password correct, request OTP verification
            return {
                'status': 'otp_required', 
                'message': 'Please enter OTP code'
            }
        else:
            self._log(f"[WARNING] Login failed - invalid password for '{username}'")
            self._record_failed_attempt(client_ip)
            return {'status': 'error', 'message': 'Invalid credentials'}
    
    def _record_failed_attempt(self, client_ip):
        """
        Record failed login attempt and implement rate limiting
        
        Args:
            client_ip (str): IP address of the client
        """
        if client_ip in self.failed_login_attempts:
            self.failed_login_attempts[client_ip]['count'] += 1
            self.failed_login_attempts[client_ip]['timestamp'] = time.time()
            count = self.failed_login_attempts[client_ip]['count']
            if count >= 3:
                self._log(f"[WARNING] Multiple failed login attempts from {client_ip} (count: {count})")
        else:
            self.failed_login_attempts[client_ip] = {
                'count': 1,
                'timestamp': time.time()
            }
    
    def handle_verify_otp(self, request, client_ip):
        """
        Handle OTP verification step of authentication
        
        Args:
            request (dict): OTP verification request with username and OTP code
            client_ip (str): Client IP address for rate limiting
            
        Returns:
            dict: Response indicating authentication success or failure
        """
        username = request.get('username')
        otp_code = request.get('otp_code')
        
        self._log(f"[INFO] Verifying OTP for user '{username}'")
        
        user = get_user(username)
        if not user:
            self._log(f"[WARNING] OTP verification failed - user '{username}' not found")
            self._record_failed_attempt(client_ip)
            return {'status': 'error', 'message': 'User not found'}
        
        otp_secret = user[4]
        
        # Verify OTP
        if OTP.verify_totp(otp_secret, otp_code):
            # Reset failed login attempts for this IP
            if client_ip in self.failed_login_attempts:
                del self.failed_login_attempts[client_ip]
            
            # Log successful login
            action = f"User login successful"
            signature = base64.b64decode(request.get('signature', ''))
            add_log(username, action, signature)
            
            is_admin = bool(user[5])
            admin_status = "administrator" if is_admin else "standard user"
            self._log(f"[SUCCESS] User '{username}' authenticated successfully as {admin_status}")
            
            return {
                'status': 'success', 
                'message': 'Login successful',
                'is_admin': is_admin
            }
        else:
            self._log(f"[WARNING] OTP verification failed for '{username}' - invalid code")
            self._record_failed_attempt(client_ip)
            return {'status': 'error', 'message': 'Invalid OTP code'}
    
    def handle_reset_password(self, request):
        """
        Handle password reset request
        
        Args:
            request (dict): Password reset request with verification info
            
        Returns:
            dict: Response indicating success or failure
        """
        username = request.get('username')
        old_password_hash = base64.b64decode(request.get('old_password_hash'))
        new_password_hash = base64.b64decode(request.get('new_password_hash'))
        new_salt = base64.b64decode(request.get('new_salt'))
        otp_code = request.get('otp_code')
        
        self._log(f"[INFO] Processing password reset for user '{username}'")
        
        user = get_user(username)
        if not user:
            self._log(f"[ERROR] Password reset failed - user '{username}' not found")
            return {'status': 'error', 'message': 'User not found'}
        
        stored_hash = user[1]
        otp_secret = user[4]
        
        # Verify old password and OTP
        if old_password_hash == stored_hash and OTP.verify_totp(otp_secret, otp_code):
            if update_password(username, new_password_hash, new_salt):
                # Log password reset
                action = f"Password reset successful"
                signature = base64.b64decode(request.get('signature', ''))
                add_log(username, action, signature)
                
                self._log(f"[SUCCESS] Password reset successful for user '{username}'")
                return {'status': 'success', 'message': 'Password reset successful'}
            else:
                self._log(f"[ERROR] Database error during password reset for '{username}'")
                return {'status': 'error', 'message': 'Failed to update password'}
        else:
            self._log(f"[WARNING] Password reset failed - invalid credentials or OTP for '{username}'")
            return {'status': 'error', 'message': 'Invalid credentials or OTP code'}
    
    def handle_upload_file(self, request):
        """
        Handle file upload request
        
        Args:
            request (dict): File upload request with encrypted file data
            
        Returns:
            dict: Response with file ID on success
        """
        username = request.get('username')
        encrypted_filename = base64.b64decode(request.get('encrypted_filename'))
        encrypted_file = base64.b64decode(request.get('encrypted_file'))
        encrypted_file_key = base64.b64decode(request.get('encrypted_file_key'))
        signature = base64.b64decode(request.get('signature', ''))
        
        file_size = len(encrypted_file)
        
        self._log(f"[INFO] Processing file upload from '{username}' (size: {file_size} bytes)")
        
        # Generate unique file ID
        file_id = str(uuid.uuid4())
        
        # For large files, store in filesystem instead of database
        if file_size > 1024 * 1024:  # If larger than 1MB
            self._log(f"[INFO] Large file detected, storing in filesystem")
            file_path = f"file_storage/{file_id}"
            with open(file_path, "wb") as f:
                f.write(encrypted_file)
            
            # Store file metadata in database (with empty encrypted_file field)
            store_file(file_id, username, encrypted_filename, b'', encrypted_file_key, file_path)
            self._log(f"[INFO] Large file saved to {file_path}")
        else:
            # Store smaller files directly in database
            store_file(file_id, username, encrypted_filename, encrypted_file, encrypted_file_key)
            self._log(f"[INFO] File stored in database")
        
        # Log file upload
        action = f"File upload: {file_id}"
        add_log(username, action, signature)
        
        self._log(f"[SUCCESS] File uploaded successfully with ID: {file_id}")
        
        return {
            'status': 'success', 
            'message': 'File uploaded successfully',
            'file_id': file_id
        }
    
    def handle_download_file(self, request):
        """
        Handle file download request with access control
        
        Args:
            request (dict): File download request with file ID
            
        Returns:
            dict: Response with encrypted file data or error
        """
        username = request.get('username')
        file_id = request.get('file_id')
        signature = base64.b64decode(request.get('signature', ''))
        
        self._log(f"[INFO] Processing file download request from '{username}' for file ID: {file_id}")
        
        # Get file from database
        file = get_file(file_id)
        if not file:
            self._log(f"[ERROR] Download failed - file ID '{file_id}' not found")
            return {'status': 'error', 'message': 'File not found'}
        
        owner = file[1]
        encrypted_filename = file[2]
        
        # Check if encrypted_file is stored in database or in filesystem
        if file[3]:  # If encrypted_file is in database
            encrypted_file = file[3]
        else:  # If encrypted_file is in filesystem
            file_path = file[5]  # Assuming column 5 contains file_path
            try:
                with open(file_path, "rb") as f:
                    encrypted_file = f.read()
                self._log(f"[INFO] Retrieved file from filesystem: {file_path}")
            except FileNotFoundError:
                self._log(f"[ERROR] File data not found at {file_path}")
                return {'status': 'error', 'message': 'File data not found'}
        
        encrypted_file_key = file[4]
        
        # Check if user is the owner or the file is shared with them
        if owner == username:
            # User is the owner
            self._log(f"[INFO] Authorized download - '{username}' is the file owner")
            
            # Log file download
            action = f"File download: {file_id} (owned)"
            add_log(username, action, signature)
            
            return {
                'status': 'success',
                'encrypted_file': base64.b64encode(encrypted_file).decode(),
                'encrypted_file_key': base64.b64encode(encrypted_file_key).decode(),
                'encrypted_filename': base64.b64encode(encrypted_filename).decode()
            }
        else:
            # Check if file is shared with the user
            self._log(f"[INFO] Checking sharing permissions for '{username}' on file {file_id}")
            conn = sqlite3.connect("server_storage.db")
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT encrypted_file_key FROM shares WHERE file_id = ? AND shared_with = ?",
                (file_id, username)
            )
            
            shared_key = cursor.fetchone()
            conn.close()
            
            if shared_key:
                self._log(f"[INFO] Authorized download - file is shared with '{username}'")
                
                # Log shared file download
                action = f"File download: {file_id} (shared by {owner})"
                add_log(username, action, signature)
                
                return {
                    'status': 'success',
                    'encrypted_file': base64.b64encode(encrypted_file).decode(),
                    'encrypted_file_key': base64.b64encode(shared_key[0]).decode(),
                    'encrypted_filename': base64.b64encode(encrypted_filename).decode()
                }
            else:
                self._log(f"[WARNING] Unauthorized file access attempt by '{username}' for file {file_id}")
                
                # Log unauthorized access attempt
                action = f"Unauthorized file access attempt: {file_id}"
                add_log(username, action, signature)
                
                return {'status': 'error', 'message': 'Access denied'}
    
    def handle_list_files(self, request):
        """
        Handle file listing request
        
        Args:
            request (dict): File listing request with username
            
        Returns:
            dict: Response with lists of own and shared files
        """
        username = request.get('username')
        
        self._log(f"[INFO] Retrieving file list for user '{username}'")
        
        # Verify user exists
        user = get_user(username)
        if not user:
            self._log(f"[ERROR] File listing failed - user '{username}' not found")
            return {'status': 'error', 'message': 'User not found'}
        
        # Get user's own files
        own_files = get_user_files(username)
        
        # Get files shared with the user
        shared_files = get_shared_files(username)
        
        self._log(f"[INFO] Found {len(own_files)} owned files and {len(shared_files)} shared files for '{username}'")
        
        # Convert to response format
        formatted_own_files = []
        for file_id, encrypted_filename in own_files:
            formatted_own_files.append({
                'file_id': file_id,
                'encrypted_filename': base64.b64encode(encrypted_filename).decode()
            })
        
        formatted_shared_files = []
        for file_id, encrypted_filename, owner, _ in shared_files:
            formatted_shared_files.append({
                'file_id': file_id,
                'encrypted_filename': base64.b64encode(encrypted_filename).decode(),
                'owner': owner
            })
        
        return {
            'status': 'success',
            'own_files': formatted_own_files,
            'shared_files': formatted_shared_files
        }
    
    def handle_share_file(self, request):
        """
        Handle file sharing request
        
        Args:
            request (dict): File sharing request with recipient and file key
            
        Returns:
            dict: Response indicating success or failure
        """
        username = request.get('username')
        file_id = request.get('file_id')
        shared_with = request.get('shared_with')
        encrypted_file_key = base64.b64decode(request.get('encrypted_file_key'))
        signature = base64.b64decode(request.get('signature', ''))
        
        self._log(f"[INFO] Processing file share request from '{username}' to '{shared_with}' for file {file_id}")
        
        # Verify both users exist
        owner = get_user(username)
        recipient = get_user(shared_with)
        
        if not owner:
            self._log(f"[ERROR] File sharing failed - owner '{username}' not found")
            return {'status': 'error', 'message': 'Owner user not found'}
            
        if not recipient:
            self._log(f"[ERROR] File sharing failed - recipient '{shared_with}' not found")
            return {'status': 'error', 'message': 'Recipient user not found'}
        
        # Verify ownership
        file = get_file(file_id)
        if not file or file[1] != username:
            self._log(f"[WARNING] Unauthorized sharing attempt - '{username}' does not own file {file_id}")
            return {'status': 'error', 'message': 'You do not own this file'}
        
        # Share file
        if share_file(file_id, username, shared_with, encrypted_file_key):
            # Log file sharing
            action = f"File share: {file_id} with {shared_with}"
            add_log(username, action, signature)
            
            self._log(f"[SUCCESS] File {file_id} shared successfully from '{username}' to '{shared_with}'")
            return {'status': 'success', 'message': 'File shared successfully'}
        else:
            self._log(f"[ERROR] Failed to share file {file_id} with '{shared_with}'")
            return {'status': 'error', 'message': 'Failed to share file'}
    
    def handle_edit_file(self, request):
        """
        Handle file editing request
        
        Args:
            request (dict): File editing request with updated file data
            
        Returns:
            dict: Response indicating success or failure
        """
        username = request.get('username')
        file_id = request.get('file_id')
        encrypted_file = base64.b64decode(request.get('encrypted_file'))
        signature = base64.b64decode(request.get('signature', ''))
        
        file_size = len(encrypted_file)
        
        self._log(f"[INFO] Processing file edit request from '{username}' for file {file_id} (size: {file_size} bytes)")
        
        # Get file from database
        file = get_file(file_id)
        if not file:
            self._log(f"[ERROR] File edit failed - file ID '{file_id}' not found")
            return {'status': 'error', 'message': 'File not found'}
        
        # Verify user is the owner
        if not verify_file_owner(file_id, username):
            self._log(f"[WARNING] Unauthorized file edit attempt by '{username}' for file {file_id}")
            
            # Log unauthorized access attempt
            action = f"Unauthorized file edit attempt: {file_id}"
            add_log(username, action, signature)
            return {'status': 'error', 'message': 'You do not have permission to edit this file'}
        
        # Check if file is stored in filesystem
        file_path = file[5] if len(file) > 5 else None
        
        if file_path:
            # Write new file content to filesystem
            try:
                with open(file_path, "wb") as f:
                    f.write(encrypted_file)
                self._log(f"[INFO] Updated file content in filesystem: {file_path}")
            except IOError as e:
                self._log(f"[ERROR] Failed to write file to filesystem: {e}")
                return {'status': 'error', 'message': 'Failed to save file'}
        
        # Update database
        if update_file_content(file_id, encrypted_file, file_path):
            # Log file edit
            action = f"File edit: {file_id}"
            add_log(username, action, signature)
            
            self._log(f"[SUCCESS] File {file_id} edited successfully by '{username}'")
            return {'status': 'success', 'message': 'File edited successfully'}
        else:
            self._log(f"[ERROR] Database update failed for file {file_id}")
            return {'status': 'error', 'message': 'Database error occurred'}
    
    def handle_delete_file(self, request):
        """
        Handle file deletion request
        
        Args:
            request (dict): File deletion request with file ID
            
        Returns:
            dict: Response indicating success or failure
        """
        username = request.get('username')
        file_id = request.get('file_id')
        signature = base64.b64decode(request.get('signature', ''))
        
        self._log(f"[INFO] Processing file deletion request from '{username}' for file {file_id}")
        
        # Get file from database
        file = get_file(file_id)
        if not file:
            self._log(f"[ERROR] File deletion failed - file ID '{file_id}' not found")
            return {'status': 'error', 'message': 'File not found'}
        
        # Verify user is the owner
        if not verify_file_owner(file_id, username):
            self._log(f"[WARNING] Unauthorized file deletion attempt by '{username}' for file {file_id}")
            
            # Log unauthorized access attempt
            action = f"Unauthorized file deletion attempt: {file_id}"
            add_log(username, action, signature)
            return {'status': 'error', 'message': 'You do not have permission to delete this file'}
        
        # Delete file from filesystem if exists
        if len(file) > 5 and file[5]:  # If file_path exists
            try:
                os.remove(file[5])
                self._log(f"[INFO] Deleted file from filesystem: {file[5]}")
            except (FileNotFoundError, PermissionError) as e:
                self._log(f"[WARNING] Error removing file {file[5]}: {e}")
        
        # Delete from database
        success, share_count = delete_file_record(file_id)
        if success:
            self._log(f"[INFO] Removed {share_count} file shares for file {file_id}")
            
            # Log file deletion
            action = f"File delete: {file_id}"
            add_log(username, action, signature)
            
            self._log(f"[SUCCESS] File {file_id} deleted successfully by '{username}'")
            return {'status': 'success', 'message': 'File deleted successfully'}
        else:
            self._log(f"[ERROR] Database deletion failed for file {file_id}")
            return {'status': 'error', 'message': 'Database error occurred'}
    
    def handle_get_logs(self, request):
        """
        Handle request to get system logs (admin only)
        
        Args:
            request (dict): Log request with username
            
        Returns:
            dict: Response with logs or access denied
        """
        username = request.get('username')
        
        self._log(f"[INFO] Processing logs request from '{username}'")
        
        # Get user
        user = get_user(username)
        if not user:
            self._log(f"[ERROR] Logs request failed - user '{username}' not found")
            return {'status': 'error', 'message': 'User not found'}
        
        # Check if user is admin
        is_admin = bool(user[5])
        if not is_admin:
            self._log(f"[WARNING] Unauthorized logs access attempt by non-admin user '{username}'")
            
            # Log unauthorized access attempt
            action = f"Unauthorized logs access attempt"
            add_log(username, action, b'')
            
            return {'status': 'error', 'message': 'Access denied'}
        
        # Get logs
        logs = get_logs(is_admin)
        
        self._log(f"[INFO] Retrieved {len(logs)} log entries for admin '{username}'")
        
        # Format logs for response
        formatted_logs = []
        for log_id, log_username, action, timestamp, signature in logs:
            formatted_logs.append({
                'log_id': log_id,
                'username': log_username,
                'action': action,
                'timestamp': timestamp,
                'signature': base64.b64encode(signature).decode() if signature else ''
            })
        
        return {
            'status': 'success',
            'logs': formatted_logs
        }

    def handle_get_salt(self, request):
        """
        Handle request for user's password salt
        
        Args:
            request (dict): Salt request with username
            
        Returns:
            dict: Response with salt or error
        """
        username = request.get('username')
        
        self._log(f"[INFO] Processing salt request for user '{username}'")
        
        # Get user's salt using the specialized function
        salt = get_user_salt(username)
        
        if salt is None:
            self._log(f"[ERROR] Salt request failed - user '{username}' not found")
            return {
                'status': 'error',
                'message': 'User not found'
            }
        
        self._log(f"[INFO] Provided salt for user '{username}'")
        return {
            'status': 'success',
            'salt': base64.b64encode(salt).decode()
        }
    
    def handle_get_public_key(self, request):
        """
        Handle request for user's public key
        
        Args:
            request (dict): Public key request with username
            
        Returns:
            dict: Response with public key or error
        """
        username = request.get('username')
        
        self._log(f"[INFO] Processing public key request for user '{username}'")
        
        # Get user from database
        user = get_user(username)
        if not user:
            self._log(f"[ERROR] Public key request failed - user '{username}' not found")
            return {
                'status': 'error',
                'message': 'User not found'
            }
        
        # Return the user's public key
        public_key = user[3]  # Assuming public_key is at index 3
        
        self._log(f"[INFO] Provided public key for user '{username}'")
        return {
            'status': 'success',
            'public_key': base64.b64encode(public_key).decode()
        }
        
    def handle_get_file_key(self, request):
        """
        Handle request for encrypted file key
        
        Args:
            request (dict): File key request with file ID
            
        Returns:
            dict: Response with encrypted file key or error
        """
        username = request.get('username')
        file_id = request.get('file_id')
        signature = base64.b64decode(request.get('signature', ''))
        
        self._log(f"[INFO] Processing file key request from '{username}' for file {file_id}")
        
        # Get file from database
        file = get_file(file_id)
        if not file:
            self._log(f"[ERROR] File key request failed - file ID '{file_id}' not found")
            return {'status': 'error', 'message': 'File not found'}
        
        owner = file[1]
        encrypted_file_key = file[4]
        
        # Verify if user is the owner
        if owner != username:
            self._log(f"[WARNING] Unauthorized file key request by '{username}' for file {file_id}")
            
            # Log unauthorized access attempt
            action = f"Unauthorized file key access attempt: {file_id}"
            add_log(username, action, signature)
            
            return {'status': 'error', 'message': 'Access denied'}
        
        # Verify signature
        signature_data = f"get_file_key:{username}:{file_id}".encode()
        user_data = get_user(username)
        
        if not user_data or not verify_signature(signature_data, signature, user_data[3]):  # user_data[3] is public_key
            self._log(f"[WARNING] Invalid signature in file key request from '{username}'")
            return {'status': 'error', 'message': 'Invalid signature'}
        
        self._log(f"[INFO] Provided file key for file {file_id} to owner '{username}'")
        return {
            'status': 'success',
            'encrypted_file_key': base64.b64encode(encrypted_file_key).decode()
        }
    
if __name__ == "__main__":
    server = Server()
    server.start()