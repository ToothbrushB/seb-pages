"""
SEB Config File Utilities
Handles encryption and decryption of Safe Exam Browser configuration files
"""

import gzip
import hashlib
import hmac
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


class SEBConfigError(Exception):
    """Custom exception for SEB config file errors"""
    pass


def _pad_pkcs7(data, block_size=16):
    """Add PKCS7 padding to data"""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def _unpad_pkcs7(data):
    """Remove PKCS7 padding from data"""
    padding_length = data[-1]
    return data[:-padding_length]


def encrypt_seb_config(xml_data, password=None):
    """
    Encrypt SEB configuration data.
    
    Args:
        xml_data (str or bytes): XML configuration data to encrypt
        password (str, optional): Password for encryption. If None, file will be unencrypted.
    
    Returns:
        bytes: Encrypted and gzipped .seb file data
    
    Raises:
        SEBConfigError: If encryption fails
    """
    try:
        # Convert string to bytes if necessary
        if isinstance(xml_data, str):
            xml_data = xml_data.encode('utf-8')
        
        # Compress the XML data
        compressed_xml = gzip.compress(xml_data)
        
        if password is None:
            # No encryption - just prefix with 'plnd' and compress
            prefixed_data = b'plnd' + compressed_xml
        else:
            # Encrypt with password using RNCryptor format
            encrypted_data = _encrypt_with_password(compressed_xml, password)
            # Prefix with 'pswd'
            prefixed_data = b'pswd' + encrypted_data
        
        # Final gzip compression
        final_data = gzip.compress(prefixed_data)
        
        return final_data
    
    except Exception as e:
        raise SEBConfigError(f"Failed to encrypt SEB config: {str(e)}")


def decrypt_seb_config(seb_file_data, password=None):
    """
    Decrypt SEB configuration file.
    
    Args:
        seb_file_data (bytes): The encrypted .seb file data
        password (str, optional): Password for decryption if file is password-protected
    
    Returns:
        bytes: Decrypted XML configuration data
    
    Raises:
        SEBConfigError: If decryption fails or password is incorrect
    """
    try:
        # First gzip decompression
        try:
            decompressed_outer = gzip.decompress(seb_file_data)
        except Exception as e:
            raise SEBConfigError(f"Failed to decompress outer gzip: {str(e)}")
        
        # Check prefix (first 4 bytes)
        if len(decompressed_outer) < 4:
            raise SEBConfigError("File too short to contain valid prefix")
        
        prefix = decompressed_outer[:4].decode('utf-8', errors='ignore')
        data = decompressed_outer[4:]
        
        # Handle different prefixes
        if prefix == 'pkhs':
            raise SEBConfigError("X.509 certificate encryption not supported. Use password encryption only.")
        
        elif prefix == 'phsk':
            raise SEBConfigError("X.509 certificate with symmetric key encryption not supported. Use password encryption only.")
        
        elif prefix == 'plnd':
            # Plain data - just decompress
            try:
                xml_data = gzip.decompress(data)
                return xml_data
            except Exception as e:
                raise SEBConfigError(f"Failed to decompress plain data: {str(e)}")
        
        elif prefix == 'pswd' or prefix == 'pwcc':
            # Password encrypted
            if password is None:
                raise SEBConfigError("Password required to decrypt this file")
            
            try:
                decrypted_data = _decrypt_with_password(data, password)
                # Decompress the decrypted data
                xml_data = gzip.decompress(decrypted_data)
                return xml_data
            except Exception as e:
                raise SEBConfigError(f"Failed to decrypt with password (wrong password?): {str(e)}")
        
        else:
            raise SEBConfigError(f"Unknown prefix: {prefix}")
    
    except SEBConfigError:
        raise
    except Exception as e:
        raise SEBConfigError(f"Failed to decrypt SEB config: {str(e)}")


def _encrypt_with_password(data, password):
    """
    Encrypt data using RNCryptor format with password.
    
    RNCryptor format:
    | version | options | encryption salt | HMAC salt | IV | ciphertext | HMAC |
    |    0    |    1    |      2-9        |   10-17   | 18-33 | 34-n-33  | n-31-n |
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Constants
    VERSION = 1
    OPTIONS = 0
    ITERATIONS = 10000
    
    # Generate random salts and IV
    encryption_salt = os.urandom(8)
    hmac_salt = os.urandom(8)
    iv = os.urandom(16)
    
    # Derive keys using PBKDF2
    encryption_key = PBKDF2(password, encryption_salt, dkLen=32, count=ITERATIONS)
    hmac_key = PBKDF2(password, hmac_salt, dkLen=32, count=ITERATIONS)
    
    # Pad data to AES block size (16 bytes)
    padded_data = _pad_pkcs7(data, 16)
    
    # Encrypt using AES-256-CBC
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_data)
    
    # Build the message (without HMAC yet)
    message = bytes([VERSION, OPTIONS]) + encryption_salt + hmac_salt + iv + ciphertext
    
    # Calculate HMAC over the entire message
    hmac_digest = hmac.new(hmac_key, message, hashlib.sha256).digest()
    
    # Append HMAC to message
    final_message = message + hmac_digest
    
    return final_message


def _decrypt_with_password(encrypted_data, password):
    """
    Decrypt data using RNCryptor format with password.
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Parse the encrypted data structure
    if len(encrypted_data) < 66:  # Minimum size: 2 + 8 + 8 + 16 + 16 + 32
        raise ValueError("Encrypted data too short")
    
    version = encrypted_data[0]
    options = encrypted_data[1]
    encryption_salt = encrypted_data[2:10]
    hmac_salt = encrypted_data[10:18]
    iv = encrypted_data[18:34]
    ciphertext = encrypted_data[34:-32]
    provided_hmac = encrypted_data[-32:]
    
    # bypass version check
    # if version != 1:
    #     raise ValueError(f"Unsupported version: {version}")
    
    # Derive keys using PBKDF2
    ITERATIONS = 10000
    encryption_key = PBKDF2(password, encryption_salt, dkLen=32, count=ITERATIONS)
    hmac_key = PBKDF2(password, hmac_salt, dkLen=32, count=ITERATIONS)
    
    # Verify HMAC
    message = encrypted_data[:-32]  # Everything except the HMAC
    calculated_hmac = hmac.new(hmac_key, message, hashlib.sha256).digest()
    
    if not hmac.compare_digest(calculated_hmac, provided_hmac):
        raise ValueError("HMAC verification failed - wrong password or corrupted data")
    
    # Decrypt using AES-256-CBC
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Remove padding
    plaintext = _unpad_pkcs7(padded_plaintext)
    
    return plaintext


# Example usage
if __name__ == "__main__":
    # Example XML config data
    example_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>allowQuit</key>
    <false/>
    <key>browserWindowAllowReload</key>
    <true/>
    <key>examSessionClearCookiesOnEnd</key>
    <true/>
</dict>
</plist>"""
    
    print("SEB Config Utilities Demo")
    print("=" * 50)
    
    # Test 1: Encrypt and decrypt with password
    print("\n1. Testing password encryption...")
    password = "testPassword123"
    encrypted = encrypt_seb_config(example_xml, password)
    print(f"   Encrypted size: {len(encrypted)} bytes")
    
    decrypted = decrypt_seb_config(encrypted, password)
    print(f"   Decrypted matches original: {decrypted.decode('utf-8') == example_xml}")
    
    # Test 2: Encrypt without password (plain)
    print("\n2. Testing plain (unencrypted) format...")
    encrypted_plain = encrypt_seb_config(example_xml, password=None)
    print(f"   Encrypted size: {len(encrypted_plain)} bytes")
    
    decrypted_plain = decrypt_seb_config(encrypted_plain, password=None)
    print(f"   Decrypted matches original: {decrypted_plain.decode('utf-8') == example_xml}")
    
    # Test 3: Try wrong password
    print("\n3. Testing wrong password...")
    try:
        decrypt_seb_config(encrypted, "wrongPassword")
        print("   ERROR: Should have failed!")
    except SEBConfigError as e:
        print(f"   Correctly rejected: {e}")
    
    print("\n" + "=" * 50)
    print("All tests completed!")
