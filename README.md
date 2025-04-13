# PolySecure System

**User Manual**

*Repository: [https://github.com/CCMKCCMK/PolySecure.git](https://github.com/CCMKCCMK/PolySecure.git)*

*Last Updated: April 12, 2025*

---

## 1. Overview

The PolySecure System is an end-to-end encrypted file storage application that allows users to securely store, share, and manage their files. This manual provides detailed instructions for deploying and using the application on Windows 11.

**Key Security Features:**

*   End-to-end encryption using AES-256-GCM
*   RSA-2048 asymmetric keys for secure key exchange
*   Two-factor authentication with Time-based One-Time Password (TOTP)
*   Secure password storage with PBKDF2-HMAC-SHA256
*   TLS/SSL encrypted communications
*   Digital signatures for non-repudiation
*   Secure file sharing between users
*   Protection against common attacks (SQL injection, path traversal)

---

## 2. System Requirements

*   Windows 11 operating system
*   Python 3.8 or higher (3.10+ recommended)
*   Minimum 4GB RAM
*   50MB free disk space (plus additional space for your files)
*   Internet connection (for server-client communication)
*   A smartphone with an authenticator app (Google Authenticator, Microsoft Authenticator, etc.)

---

## 3. Installation & Deployment Guide

### 3.1 Installing Python on Windows 11

If you don't have Python installed on your Windows 11 system:

1.  Visit the official Python website at [https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/)
2.  Download the latest Python installer (Python 3.10 or higher recommended)
3.  Run the installer and **ensure you check the box that says "Add Python to PATH"**.
4.  Choose "Install Now" for a standard installation.
5.  Wait for the installation to complete.

> **Note:** To verify Python was installed correctly, open Command Prompt and type: `python --version`. You should see the Python version number.

### 3.2 Downloading the Application

1.  Clone the repository or download the application files:
    *   **Using Git:**
        ```bash
        git clone https://github.com/CCMKCCMK/PolySecure.git
        cd PolySecure
        ```
    *   **Manual Download:** Download the ZIP file from the GitHub repository. Extract all files to a folder on your computer (e.g., `C:\PolySecure`)
2.  Make sure all the following files are present:
    *   `client.py`
    *   `server.py`
    *   `crypto_utils.py`
    *   `db_utils.py`
    *   `otp.py`
    *   `requirements.txt`
    *   `README.md`

### 3.3 Setting Up a Virtual Environment (Recommended)

Using a virtual environment keeps project dependencies isolated.

1.  Open Command Prompt in the project directory (`PolySecure`).
2.  Create a virtual environment named `venv`:
    ```bash
    python -m venv venv
    ```
3.  Activate the virtual environment:
    ```bash
    venv\Scripts\activate
    ```
    Your command prompt should now show `(venv)` at the beginning.

> **Note:** To deactivate the virtual environment later, simply type `deactivate`.

### 3.4 Installing Dependencies

Install the required Python packages within the activated virtual environment:

1.  Ensure your virtual environment is active (`(venv)` should be visible in the prompt).
2.  Install the required packages using pip:
    ```bash
    pip install -r requirements.txt
    ```

> **Note:** The `requirements.txt` file includes: `cryptography`, `qrcode`.

### 3.5 Installing an Authenticator App

Install an authenticator app on your smartphone for two-factor authentication (2FA):

1.  On your smartphone, go to the app store (Google Play Store or Apple App Store)
2.  Search for one of the following authenticator apps:
    *   Google Authenticator
    *   Microsoft Authenticator
    *   Authy
3.  Download and install the app

> **Note:** You'll use this app later to scan a QR code during user registration.

### 3.6 Configuring Windows Firewall (Optional)

If running the server and client on different machines on the same network:

1.  Search for "Windows Defender Firewall" and open "Advanced settings".
2.  Go to "Inbound Rules" -> "New Rule...".
3.  Select "Port", then "TCP", and specify port `9999`.
4.  Select "Allow the connection".
5.  Choose the appropriate network types (e.g., Private).
6.  Name the rule (e.g., "Secure Storage Server") and click Finish.

---

## 4. Starting the Application

**Important:** Always activate the virtual environment (`venv\Scripts\activate`) in each new Command Prompt window before running the server or client.

### 4.1 Starting the Server

1.  Open Command Prompt and navigate to the project directory.
2.  Activate the virtual environment: `venv\Scripts\activate`
3.  Start the server:
    ```bash
    python server.py
    ```
4.  You should see a server banner and initialization messages:
    ```
    ┌───────────────────────────────────────────────────────┐
    │                                                       │
    │   POLYSECURE SERVER                                   │
    │   End-to-End Encrypted File Storage                   │
    │                                                       │
    │   Version: 1.0                                        │
    │   Implements: TLS, AES-GCM, RSA, PBKDF2, TOTP         │
    │                                                       │
    └───────────────────────────────────────────────────────┘

    [2025-04-13 17:18:40] [INFO] Initializing database...
    [2025-04-13 17:18:40] [SUCCESS] Database initialized
    [2025-04-13 17:18:40] [INFO] Creating admin account...
    [2025-04-13 17:18:40] [INFO] Admin account already exists
    [2025-04-13 17:18:40] [INFO] Creating communication session for admin...
    [2025-04-13 17:18:40] [SUCCESS] Communication session created for admin at admin@localhost
    [2025-04-13 17:18:40] [SUCCESS] Admin account created or verified
    [2025-04-13 17:18:40] [INFO] Generating server cryptographic keys...
    [2025-04-13 17:18:41] [SUCCESS] Server keys generated
    [2025-04-13 17:18:41] [INFO] Setting up file storage...
    [2025-04-13 17:18:41] [SUCCESS] File storage ready
    [2025-04-13 17:18:41] [INFO] Configuring SSL/TLS...
    [2025-04-13 17:18:41] [SUCCESS] SSL/TLS configured
    [2025-04-13 17:18:41] [SUCCESS] Server started on localhost:9999
    [2025-04-13 17:18:41] [INFO] Waiting for client connections...
    ```

> **Important:** Keep the server window open. Closing it will shut down the server.

### 4.2 Starting the Client

1.  Open a **new** Command Prompt window.
2.  Navigate to the project directory.
3.  Activate the virtual environment: `venv\Scripts\activate`
4.  Start the client:
    ```bash
    python client.py
    ```
4.  You should see the client welcome banner and menu:
    ```
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║   POLYSECURE SYSTEM                               ║
    ║   End-to-End Encrypted File Storage               ║
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝

    [i] Connecting to server...
    [✓] Connected to localhost:9999
    [i] Establishing secure session...
    [✓] Secure session established

    PolySecure Client - Not Logged In
    1. Register
    2. Login
    0. Exit

    Enter your choice:
    ```

---

## 5. Using the Application

### 5.1 User Registration

Before using the system, you need to register a user account:

1.  From the client menu, select **1** to register
2.  Enter a username of your choice
3.  Enter a secure password (should include uppercase, lowercase, numbers)
4.  Confirm your password when prompted
5.  The client will generate cryptographic keys and register your account
6.  After successful registration, the system will:
    *   Generate a TOTP (Time-based One-Time Password) secret
    *   Save a QR code image in the `client_storage` folder
7.  Navigate to the `client_storage` folder and find the QR code image named `username_otp_qr.png`
8.  Open the image and scan it with your authenticator app

> **Note:** Make sure to scan the QR code with your authenticator app. You'll need the generated codes for logging in.

### 5.2 User Login

To access the system:

1.  From the client menu, select **2** to login
2.  Enter your username
3.  Enter your password
4.  When prompted for an OTP code, open your authenticator app and enter the 6-digit code shown for "SecureStorage"
5.  After successful authentication, you'll see the main menu with additional options

> **Administrator Login:** The system has a built-in admin account (username: `admin`, password: `admin123`) for management purposes. In a production environment, change this password immediately.

### 5.3 File Operations

#### 5.3.1 Uploading Files

1.  From the main menu, select **1** to upload a file
2.  Enter the full path to the file (e.g., `C:\Users\YourName\Documents\example.txt`)
3.  The system will encrypt the file and upload it to the server
4.  You'll receive a file ID upon successful upload (save this ID for later reference)

#### 5.3.2 Downloading Files

1.  From the main menu, select **2** to download a file
2.  Enter the file ID of the file you want to download
3.  The system will retrieve, decrypt, and save the file to the `client_downloads` folder
4.  You can access the downloaded file in the `client_downloads` directory

#### 5.3.3 Listing Files

1.  From the main menu, select **3** to list your files
2.  The system will display:
    *   Files you own (with their IDs and filenames)
    *   Files others have shared with you (with IDs, filenames, and owner names)

#### 5.3.4 Sharing Files

1.  From the main menu, select **4** to share a file
2.  First, the system will display your files to help you choose which one to share
3.  Enter the file ID of the file you want to share
4.  Enter the username of the recipient
5.  The system will securely re-encrypt the file key for the recipient
6.  The recipient will now be able to see and download this file in their shared files list

#### 5.3.5 Editing Files

1.  From the main menu, select **5** to edit a file
2.  Your files will be listed to help you choose which one to edit
3.  Enter the file ID of the file you want to edit
4.  The system will download and decrypt the file for editing
5.  Edit the file using any text editor
6.  After editing, press Enter in the client to continue
7.  The system will encrypt and upload the modified file

#### 5.3.6 Deleting Files

1.  From the main menu, select **6** to delete a file
2.  Your files will be listed to help you choose which one to delete
3.  Enter the file ID of the file you want to delete
4.  Confirm the deletion when prompted
5.  The file will be permanently removed from the server

> **Warning:** File deletion is permanent and cannot be undone. Make sure you have a backup if needed.

### 5.4 Account Management

#### 5.4.1 Changing Password

1.  From the main menu, select **7** to reset your password
2.  Enter your current password
3.  Enter your new password (should include uppercase, lowercase, numbers)
4.  Confirm your new password
5.  Enter the OTP code from your authenticator app
6.  The system will update your password and re-encrypt your stored private key

> **Note:** The 2FA requirement for password changes adds an additional layer of security.

#### 5.4.2 Admin Features

When logged in as an administrator (`admin`):

1.  From the main menu, select **8** to view system logs
2.  The system will display all user activities including:
    *   User registrations and logins
    *   File uploads, downloads, and shares
    *   Password changes and other account activities

#### 5.4.3 Logging Out

1.  From the main menu, select **9** to logout
2.  The system will securely clear your session data
3.  You'll be returned to the login menu

#### 5.4.4 Exiting the Application

1.  From the main menu (or login menu), select **0** to exit
2.  The application will close after clearing sensitive data from memory

---

## 6. Security Best Practices

*   Use strong, unique passwords.
*   Keep your authenticator app secure and consider backing up OTP secrets safely.
*   Share files only with trusted users.
*   Keep your OS and Python updated.
*   Change the default admin password (`admin123`) immediately after the first run.
*   For production, use proper SSL certificates instead of the self-signed ones generated.

---

## 7. Troubleshooting

### 7.1 Connection Issues

**Problem:** Client cannot connect to the server

**Solutions:**

*   Ensure the server is running
*   Check if the server address and port are correct in the client (default: localhost:9999)
*   Verify that no firewall is blocking the connection
*   If running on separate machines, ensure the server IP address is correctly specified

### 7.2 Authentication Problems

**Problem:** Unable to log in despite correct credentials

**Solutions:**

*   Ensure your authenticator app's time is synchronized (some apps have a sync feature)
*   Check that you're using the correct username and password
*   If you've tried multiple failed logins, wait a minute (rate limiting may be in effect)
*   Verify that your OTP secret was set up correctly in your authenticator app

### 7.3 OTP Issues

**Problem:** OTP codes not being accepted

**Solutions:**

*   Ensure your device's time is accurate (OTP is time-based)
*   Try entering a new code (they change every 30 seconds)
*   Re-scan the QR code if persistent issues occur
*   If you lost access to your OTP, contact an administrator to reset your account

### 7.4 File Operation Errors

**Problem:** Unable to upload/download files

**Solutions:**

*   Check that the file path is correct (absolute path recommended)
*   Ensure you have read/write permissions on the directories
*   For large files, make sure the connection remains stable during transfer
*   Verify that the `client_downloads` and `client_storage` directories exist

### 7.5 Installation Errors

**Problem:** Dependency installation failing

**Solutions:**

*   Ensure you're using a compatible Python version (3.8+)
*   Try installing packages individually:
    ```bash
    pip install cryptography==41.0.3 qrcode==7.4.2 pillow==10.0.0
    ```
*   Run Command Prompt as Administrator when installing packages
*   Check your internet connection

---

## 8. Technical Information

### 8.1 System Architecture

The Secure Storage System uses a client-server architecture:

*   **Server (`server.py`)**: Handles user authentication, file storage, and access control
*   **Client (`client.py`)**: Provides the user interface and handles encryption/decryption
*   **Database (`server_storage.db`)**: SQLite database for storing user data, encrypted files, and logs
*   **Utility Modules**: `crypto_utils.py` (cryptography functions), `db_utils.py` (database operations), and `otp.py` (two-factor authentication)

The system implements a true end-to-end encryption approach where:

*   Files are encrypted on the client before being sent to the server
*   The server never has access to unencrypted file contents or encryption keys
*   Even the database administrator cannot access your files without your keys

### 8.2 Directory Structure

```
/PolySecure
|-- client.py             # Client application
|-- server.py             # Server application
|-- crypto_utils.py       # Cryptography functions
|-- db_utils.py           # Database functions
|-- otp.py                # OTP functions
|-- requirements.txt      # Dependencies
|-- README.md             # This manual
|-- server.crt            # SSL certificate (generated)
|-- server.key            # SSL private key (generated)
|-- server_storage.db     # Server database (created)
|-- /venv/                # Virtual environment directory (created)
|-- /client_downloads/    # Default location for downloaded files (created)
|-- /client_storage/      # Client keys and QR codes (created)
|-- /file_storage/        # Server-side storage for large files (created)
|-- /__pycache__/         # Python cache (created)
```

### 8.3 Default Configuration

*   **Server Address:** localhost (127.0.0.1)
*   **Server Port:** 9999
*   **Admin Username:** admin
*   **Admin Password:** admin123
*   **SSL/TLS:** Enabled (self-signed certificate)

> **Important:** For production deployment, modify these defaults in the source code and generate proper SSL certificates.

---

© 2025 PolySecure System
This document is confidential and contains proprietary information.
