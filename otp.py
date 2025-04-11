import base64
import os
import hmac
import hashlib
import time
import qrcode
from io import BytesIO

class OTP:
    @staticmethod
    def generate_secret():
        """Generate a random secret key for TOTP"""
        return base64.b32encode(os.urandom(20)).decode('utf-8')
    
    @staticmethod
    def get_hotp_token(secret, intervals_no):
        """Generate HMAC-based OTP"""
        key = base64.b32decode(secret, True)
        msg = intervals_no.to_bytes(8, byteorder='big')
        h = hmac.new(key, msg, hashlib.sha1).digest()
        
        offset = h[19] & 0xf
        code = ((h[offset] & 0x7f) << 24 |
                (h[offset + 1] & 0xff) << 16 |
                (h[offset + 2] & 0xff) << 8 |
                (h[offset + 3] & 0xff))
        
        return code % 10**6
    
    @staticmethod
    def get_totp_token(secret):
        """Generate Time-based OTP"""
        return OTP.get_hotp_token(secret, intervals_no=int(time.time()) // 30)
    
    @staticmethod
    def verify_totp(secret, token):
        """Verify a TOTP token"""
        # Check current and adjacent intervals to account for time drift
        for i in range(-1, 2):
            interval = int(time.time()) // 30 + i
            if OTP.get_hotp_token(secret, interval) == int(token):
                return True
        return False
    
    @staticmethod
    def generate_qr_code(secret, username):
        """Generate a QR code for easy setup in authenticator apps"""
        # Create the OTP auth URL (compatible with Google Authenticator)
        otp_auth_url = f"otpauth://totp/SecureStorage:{username}?secret={secret}&issuer=SecureStorage"
        
        # Generate QR code image
        img = qrcode.make(otp_auth_url)
        buffer = BytesIO()
        img.save(buffer)
        
        return buffer.getvalue()
