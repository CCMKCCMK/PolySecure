import sqlite3
from datetime import datetime

# Initialize database with required tables
def init_db(db_path="server_storage.db"):
    """
    Initialize database with required tables for users, files, shares and logs
    
    Args:
        db_path (str): Path to SQLite database file
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Users table stores user account information
    # - username: Unique user identifier
    # - password_hash: Hashed password 
    # - salt: Random salt used in password hashing
    # - public_key: User's public key for asymmetric encryption
    # - otp_secret: Secret for 2FA (optional)
    # - is_admin: Boolean flag for admin privileges
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash BLOB NOT NULL,
        salt BLOB NOT NULL,
        public_key BLOB NOT NULL,
        otp_secret BLOB,
        is_admin INTEGER DEFAULT 0
    )
    ''')
    
    # Files table stores encrypted files and metadata
    # - file_id: Unique file identifier
    # - owner: Username of file owner
    # - encrypted_filename: Encrypted original filename
    # - encrypted_file: Encrypted file content (if stored in DB)
    # - encrypted_file_key: Encrypted symmetric key
    # - upload_time: Timestamp of last upload/modification
    # - file_path: Path to file on filesystem (if stored on disk)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        file_id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        encrypted_filename BLOB NOT NULL,
        encrypted_file BLOB,
        encrypted_file_key BLOB NOT NULL,
        upload_time TIMESTAMP NOT NULL,
        file_path TEXT,
        FOREIGN KEY (owner) REFERENCES users(username)
    )
    ''')
    
    # Shares table tracks file sharing between users
    # - id: Auto-incrementing share ID
    # - file_id: ID of shared file
    # - shared_with: Username of user file is shared with
    # - encrypted_file_key: File key encrypted with recipient's public key
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id TEXT NOT NULL,
        shared_with TEXT NOT NULL,
        encrypted_file_key BLOB NOT NULL,
        FOREIGN KEY (file_id) REFERENCES files(file_id),
        FOREIGN KEY (shared_with) REFERENCES users(username),
        UNIQUE (file_id, shared_with)
    )
    ''')
    
    # Logs table stores audit trail of user actions
    # - log_id: Auto-incrementing log ID
    # - username: User who performed the action
    # - action: Description of the action
    # - timestamp: When action occurred
    # - signature: Digital signature for log 
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        timestamp TIMESTAMP NOT NULL,
        signature BLOB NOT NULL
    )
    ''')
    
    # # Create initial admin account if not exists
    # cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    # if not cursor.fetchone():
    #     from crypto_utils import hash_password, generate_key_pair
    #     import os
        
    #     admin_password = "admin123"  # This should be changed in production
    #     key, salt = hash_password(admin_password)
    #     private_key, public_key = generate_key_pair()
        
    #     cursor.execute(
    #         "INSERT INTO users (username, password_hash, salt, public_key, is_admin) VALUES (?, ?, ?, ?, 1)",
    #         ("admin", key, salt, public_key)
    #     )
    
    conn.commit()
    conn.close()

# User management functions
def register_user(username, password_hash, salt, public_key, otp_secret=None):
    """
    Register a new user in the database
    
    Args:
        username (str): Username
        password_hash (bytes): Hashed password
        salt (bytes): Password salt
        public_key (bytes): User's public key
        otp_secret (bytes, optional): 2FA secret
        
    Returns:
        bool: True if registration successful, False if username exists
    """
    conn = sqlite3.connect("server_storage.db")
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, public_key, otp_secret) VALUES (?, ?, ?, ?, ?)",
            (username, password_hash, salt, public_key, otp_secret)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_user(username):
    """
    Get user record from database
    
    Args:
        username (str): Username to lookup
        
    Returns:
        tuple: User record or None if not found
    """
    conn = sqlite3.connect("server_storage.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    conn.close()
    return user

def get_user_salt(username):
    """
    Retrieve user's password salt for password verification
    
    Args:
        username (str): Username to lookup
        
    Returns:
        bytes: User's password salt or None if user not found or error occurs
    """
    conn = sqlite3.connect("server_storage.db")
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        return result[0] if result else None
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    finally:
        conn.close()

def update_password(username, new_password_hash, new_salt):
    """
    Update user's password hash and salt
    
    Args:
        username (str): Username
        new_password_hash (bytes): New hashed password
        new_salt (bytes): New password salt
        
    Returns:
        bool: True if password updated successfully, False otherwise
    """
    conn = sqlite3.connect("server_storage.db")
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
        (new_password_hash, new_salt, username)
    )
    
    conn.commit()
    conn.close()
    return cursor.rowcount > 0

# File management functions
def store_file(file_id, owner, encrypted_filename, encrypted_file, encrypted_file_key, file_path=None):
    """
    Store an encrypted file in the database or filesystem
    
    Args:
        file_id (str): Unique file identifier
        owner (str): Username of file owner
        encrypted_filename (bytes): Encrypted original filename
        encrypted_file (bytes): Encrypted file content
        encrypted_file_key (bytes): Encrypted symmetric key
        file_path (str, optional): Path if file stored in filesystem
        
    Note:
        If file_path is provided, encrypted_file is not stored in database
        Instead, file content is written to filesystem at file_path
    """
    conn = sqlite3.connect("server_storage.db")
    cursor = conn.cursor()
    
    upload_time = datetime.now().isoformat()
    
    if file_path:
        # If file is stored in file system
        cursor.execute(
            "INSERT INTO files (file_id, owner, encrypted_filename, encrypted_file, encrypted_file_key, upload_time, file_path) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (file_id, owner, encrypted_filename, b'', encrypted_file_key, upload_time, file_path)
        )
    else:
        # If file is stored directly in database
        cursor.execute(
            "INSERT INTO files (file_id, owner, encrypted_filename, encrypted_file, encrypted_file_key, upload_time) VALUES (?, ?, ?, ?, ?, ?)",
            (file_id, owner, encrypted_filename, encrypted_file, encrypted_file_key, upload_time)
        )
    
    conn.commit()
    conn.close()

def get_file(file_id):
    """
    Retrieve file record from database
    
    Args:
        file_id (str): File ID to lookup
        
    Returns:
        tuple: File record containing all columns or None if not found
        (file_id, owner, encrypted_filename, encrypted_file, encrypted_file_key, upload_time, file_path)
    """
    conn = sqlite3.connect("server_storage.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM files WHERE file_id = ?", (file_id,))
    file = cursor.fetchone()
    
    conn.close()
    return file

def get_user_files(username):
    """
    Get all files owned by a user
    
    Args:
        username (str): Username to lookup files for
        
    Returns:
        list: List of tuples containing (file_id, encrypted_filename) for all user's files
    """
    conn = sqlite3.connect("server_storage.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT file_id, encrypted_filename FROM files WHERE owner = ?", (username,))
    files = cursor.fetchall()
    
    conn.close()
    return files

def get_shared_files(username):
    """
    Get all files shared with a user
    
    Args:
        username (str): Username to lookup shared files for
        
    Returns:
        list: List of tuples containing (file_id, encrypted_filename, owner, encrypted_file_key)
        for all files shared with user
    """
    conn = sqlite3.connect("server_storage.db")
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT f.file_id, f.encrypted_filename, f.owner, s.encrypted_file_key 
        FROM files f 
        JOIN shares s ON f.file_id = s.file_id 
        WHERE s.shared_with = ?
    """, (username,))
    
    shared_files = cursor.fetchall()
    conn.close()
    return shared_files

def share_file(file_id, owner, shared_with, encrypted_file_key):
    """
    Share a file with another user
    
    Args:
        file_id (str): ID of file to share
        owner (str): Username of file owner
        shared_with (str): Username of user to share with
        encrypted_file_key (bytes): File key encrypted with recipient's public key
        
    Returns:
        bool: True if share created successfully, False if share exists or owner verification fails
    """
    conn = sqlite3.connect("server_storage.db")
    cursor = conn.cursor()
    
    # Verify ownership
    cursor.execute("SELECT owner FROM files WHERE file_id = ?", (file_id,))
    result = cursor.fetchone()
    if not result or result[0] != owner:
        conn.close()
        return False
    
    try:
        cursor.execute(
            "INSERT INTO shares (file_id, shared_with, encrypted_file_key) VALUES (?, ?, ?)",
            (file_id, shared_with, encrypted_file_key)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def update_file_content(file_id, encrypted_file, file_path=None):
    """
    Update file content in database or filesystem
    
    Args:
        file_id (str): File ID
        encrypted_file (bytes): New encrypted file content
        file_path (str, optional): Path if file is stored in filesystem
        
    Returns:
        bool: True if successful, False otherwise
    """
    conn = sqlite3.connect("server_storage.db")
    cursor = conn.cursor()
    
    try:
        if file_path:
            # Update metadata only if file is stored in filesystem
            cursor.execute(
                "UPDATE files SET upload_time = ? WHERE file_id = ?",
                (datetime.now().isoformat(), file_id)
            )
        else:
            # Update content in database
            cursor.execute(
                "UPDATE files SET encrypted_file = ?, upload_time = ? WHERE file_id = ?",
                (encrypted_file, datetime.now().isoformat(), file_id)
            )
            
        conn.commit()
        conn.close()
        return True
        
    except sqlite3.Error as e:
        conn.close()
        return False

def delete_file_record(file_id):
    """
    Delete file and its shares from database
    
    Args:
        file_id (str): File ID to delete
        
    Returns:
        tuple: (success, share_count) where success is bool and share_count is number of shares deleted
    """
    conn = sqlite3.connect("server_storage.db")
    cursor = conn.cursor()
    
    try:
        # Delete shares first
        cursor.execute("DELETE FROM shares WHERE file_id = ?", (file_id,))
        share_count = cursor.rowcount
        
        # Delete file record
        cursor.execute("DELETE FROM files WHERE file_id = ?", (file_id,))
        
        conn.commit()
        conn.close()
        return True, share_count
        
    except sqlite3.Error as e:
        conn.close() 
        return False, 0

def verify_file_owner(file_id, username):
    """
    Verify if user is the owner of the file
    
    Args:
        file_id (str): File ID
        username (str): Username to verify
        
    Returns:
        bool: True if user is owner, False otherwise
    """
    conn = sqlite3.connect("server_storage.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT owner FROM files WHERE file_id = ?", (file_id,))
    result = cursor.fetchone()
    
    conn.close()
    
    if not result:
        return False
    return result[0] == username

# Log functions
def add_log(username, action, signature):
    """
    Add an audit log entry
    
    Args:
        username (str): User who performed the action
        action (str): Description of the action
        signature (bytes): Digital signature of log entry
    """
    conn = sqlite3.connect("server_storage.db")
    cursor = conn.cursor()
    
    timestamp = datetime.now().isoformat()
    
    cursor.execute(
        "INSERT INTO logs (username, action, timestamp, signature) VALUES (?, ?, ?, ?)",
        (username, action, timestamp, signature)
    )
    
    conn.commit()
    conn.close()

def get_logs(is_admin=False):
    """
    Retrieve audit logs
    
    Args:
        is_admin (bool): Whether requesting user is an admin
        
    Returns:
        list: List of log entries if user is admin, empty list otherwise
        Each log entry is tuple of (log_id, username, action, timestamp, signature)
    """
    if not is_admin:
        return []
        
    conn = sqlite3.connect("server_storage.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC")
    logs = cursor.fetchall()
    
    conn.close()
    return logs
