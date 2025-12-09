from sebConfigUtils import *
import plistlib
import json
import hashlib
import base64
from datetime import datetime
import gzip


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
    
    # Make a copy to avoid modifying original
    config_dict = dict(plist_data)
    
    # Remove originatorVersion key
    if 'originatorVersion' in config_dict:
        del config_dict['originatorVersion']
    
    # Convert to SEB-JSON format
    seb_json = _convert_to_seb_json(config_dict)
    
    # Generate SHA256 hash
    hash_bytes = hashlib.sha256(seb_json.encode('utf-8')).digest()
    
    # Convert to Base16 (hex) lowercase string
    config_key = hash_bytes.hex().lower()
    
    return config_key


def _convert_to_seb_json(obj):
    """
    Convert plist object to SEB-JSON string format.
    
    Special requirements:
    - No whitespace or formatting
    - No character escaping
    - Dictionaries must be alphabetically sorted by keys
    - Empty dictionaries are removed
    - Proper type conversions for data/date/real types
    """
    return _to_seb_json_recursive(obj)


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
        return json.dumps(obj)
    
    elif isinstance(obj, str):
        # Escape only what JSON requires, but don't escape backslashes
        # We'll use json.dumps but need to handle backslash specially
        escaped = json.dumps(obj, ensure_ascii=False)
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
        
        # Sort keys alphabetically (case-insensitive)
        sorted_keys = sorted(obj.keys(), key=lambda k: k.lower())
        
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


def create_seb_from_json(json_file_path, output_seb_path, password):
    """
    Create a password-encrypted .seb file from a JSON config file.
    
    Args:
        json_file_path (str): Path to input JSON config file
        output_seb_path (str): Path for output .seb file
        password (str): Password for encryption
    
    Returns:
        str: Config key hash for the created .seb file
    """
    # Step 1: Read JSON config file
    with open(json_file_path, 'r', encoding='utf-8') as f:
        config_dict = json.load(f)
    
    # generate 24 byte salt in base 64 for examKeySalt
    salt = os.urandom(24)
    config_dict["examKeySalt"] = base64.b64encode(salt).decode('ascii')
    
    # Step 2: Convert JSON dict to plist XML format
    plist_xml = plistlib.dumps(config_dict, fmt=plistlib.FMT_XML)
    
    encrypted_data = encrypt_seb_config(plist_xml, password=password)
    
    # Step 8: Save as .seb file
    with open(output_seb_path, 'wb') as f:
        f.write(encrypted_data)
    
    print(f"Created .seb file: {output_seb_path}")
    
if __name__ == '__main__':
    password="123"
    with open("Dawson_reencrypted.seb", 'rb') as f:
            seb_file_data = f.read()
    decrypted = decrypt_seb_config(seb_file_data, password=password)
    print(decrypted.decode('utf-8'))
    # reencrypted = encrypt_seb_config(decrypted, password=password)
    # with open("Dawson_reencrypted.seb", 'wb') as f:
        # f.write(reencrypted)
        
