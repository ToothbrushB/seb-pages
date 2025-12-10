"""
SEB Config File Utilities
Handles encryption and decryption of Safe Exam Browser configuration files
"""

import gzip
import rncryptor
import hashlib
import hmac
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import plistlib
import json
import hashlib
import base64
from datetime import datetime
import gzip

class SEBConfigError(Exception):
    """Custom exception for SEB config file errors"""
    pass

class RNCryptor_modified(rncryptor.RNCryptor):
    def post_decrypt_data(self, data):
        data = data[:-(data[-1])]
        return data

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
            encrypted_data = RNCryptor_modified().encrypt(compressed_xml, password)
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
        seb_file_data (bytes or str): The encrypted .seb file data or file path
        password (str, optional): Password for decryption if file is password-protected
    
    Returns:
        bytes: Decrypted XML configuration data
    
    Raises:
        SEBConfigError: If decryption fails or password is incorrect
    """
    if isinstance(seb_file_data, str):
        # Assume it's a file path
        with open(seb_file_data, 'rb') as f:
            seb_file_data = f.read()
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
                decrypted_data = RNCryptor_modified().decrypt(data, password)
                # Decompress the decrypted data
                xml_data = gzip.decompress(decrypted_data)
                return plistlib.loads(xml_data)
            except Exception as e:
                raise SEBConfigError(f"Failed to decrypt with password (wrong password?): {str(e)}")
        
        else:
            raise SEBConfigError(f"Unknown prefix: {prefix}")
    
    except SEBConfigError:
        raise
    except Exception as e:
        raise SEBConfigError(f"Failed to decrypt SEB config: {str(e)}")


def generate_config_key(plist_data):
    """
    Generate SEB Config Key from plist data.
    
    Args:
        plist_data (dict or bytes): Either a dict from plistlib or raw XML bytes
    
    Returns:
        str: 64-character hex string (SHA256 hash)
    """
    # If bytes, parse as plist first
    if isinstance(plist_data, bytes):
        plist_data = plistlib.loads(plist_data)
    elif isinstance(plist_data, str):
        plist_data = plistlib.loads(plist_data.encode('utf-8'))
    # Make a copy to avoid modifying original
    config_dict = dict(plist_data)
    
    # Remove originatorVersion key
    if 'originatorVersion' in config_dict:
        del config_dict['originatorVersion']
    
    # Convert to SEB-JSON format
    seb_json = _to_seb_json_recursive(config_dict)
    
    with open("debug_seb.json", 'w', encoding='utf-8') as f:
        f.write(seb_json)
    
    # Generate SHA256 hash
    hash_bytes = hashlib.sha256(seb_json.encode('utf-8')).digest()
    
    # Convert to Base16 (hex) lowercase string
    config_key = hash_bytes.hex().lower()
    
    return config_key

def _to_seb_json_recursive(obj):
    """Recursively convert objects to SEB-JSON format"""
    
    if obj is None:
        return 'null'
    
    elif isinstance(obj, bool):
        # Must check bool before int (bool is subclass of int)
        return 'true' if obj else 'false'
    
    elif isinstance(obj, int):
        return str(obj)
    
    elif isinstance(obj, float):
        # Round floating point numbers appropriately
        # JSON will handle rounding (e.g., 0.10000000000000001 -> 0.1)
        if (obj - int(obj)) == 0:
            return str(int(obj))
        return json.dumps(obj)
    
    elif isinstance(obj, str):
        # Escape only what JSON requires, but don't escape backslashes
        # We'll use json.dumps but need to handle backslash specially
        escaped = json.dumps(obj, ensure_ascii=False)
        if '\\\\' in escaped:
            escaped = escaped.replace('\\\\', '\\')
        return escaped
    
    elif isinstance(obj, bytes):
        # Convert bytes/data to Base64 string
        b64_string = base64.b64encode(obj).decode('ascii')
        return json.dumps(b64_string)
    
    elif isinstance(obj, datetime):
        # Convert datetime to ISO 8601 format string
        iso_string = obj.isoformat()
        return json.dumps(iso_string)
    
    elif isinstance(obj, dict):
        # Remove empty dictionaries
        if len(obj) == 0:
            return None
        
        # Sort keys alphabetically (by ascii value)
        sorted_keys = sorted(obj.keys(), key=lambda x: x.lower())
        
        # Build JSON object
        items = []
        for key in sorted_keys:
            value = obj[key]
            
            # Recursively process nested structures
            if isinstance(value, dict):
                json_value = _to_seb_json_recursive(value)
                # Skip empty dictionaries
                if json_value is None:
                    continue
            elif isinstance(value, list):
                json_value = _to_seb_json_recursive(value)
            else:
                json_value = _to_seb_json_recursive(value)
            
            # No whitespace, format as "key":value
            items.append(f'"{key}":{json_value}')
        
        # Return formatted dict without spaces
        return '{' + ','.join(items) + '}'
    
    elif isinstance(obj, list):
        # Process array elements, including nested dicts
        items = []
        for item in obj:
            if isinstance(item, dict):
                json_item = _to_seb_json_recursive(item)
                # Skip empty dictionaries in arrays
                if json_item is not None:
                    items.append(json_item)
            else:
                items.append(_to_seb_json_recursive(item))
        
        # Return formatted array without spaces
        return '[' + ','.join(items) + ']'
    
    else:
        # Fallback for any other types
        return json.dumps(obj, ensure_ascii=False)


def create_seb_from_json(json, password, output_seb_path=None, debug=False):
    """
    Create a password-encrypted .seb file from a JSON config file.
    
    Args:
        json (str): Path to input JSON config file
        output_seb_path (str): Path for output .seb file
        password (str): Password for encryption
        debug (bool): If True, save intermediate plist XML for debugging
    
    Returns:
        (bytes, str): Encrypted .seb data and config key hash for the created .seb file
    """
    # Step 1: Read JSON config file
    if isinstance(json, str):
        with open(json, 'r', encoding='utf-8') as f:
            config_dict = json.load(f)
    else:
        config_dict = json
    # generate 24 byte salt in base 64 for examKeySalt
    salt = os.urandom(24)
    config_dict["examKeySalt"] = salt
    
    # Step 2: Convert JSON dict to plist XML format
    plist_xml = plistlib.dumps(config_dict, fmt=plistlib.FMT_XML)
    
    if debug:
        with open("debug_plist.xml", 'wb') as f:
            f.write(plist_xml)
    
    ck = generate_config_key(plist_xml)
    encrypted_data = encrypt_seb_config(plist_xml, password=password)
    
    # Step 8: Save as .seb file
    if output_seb_path is None:
        return (encrypted_data, ck)
    else:
        with open(output_seb_path, 'wb') as f:
            f.write(encrypted_data)
        return (encrypted_data, ck)