import struct
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

def encrypt_3des(key, data):
    """
    Encrypt data using Triple DES (3DES).
    
    Args:
        key (bytes): The encryption key (must be 16 or 24 bytes long)
        data (bytes): The data to encrypt
        
    Returns:
        bytes: The encrypted data
    """
    # Ensure the key is the correct length (24 bytes for Triple DES)
    if len(key) == 16:
        # If key is 16 bytes, extend it to 24 bytes by appending the first 8 bytes
        key = key + key[:8]
    elif len(key) != 24:
        # If key is not 16 or 24 bytes, pad or truncate it
        key = key.ljust(24, b'\0')[:24]
    
    # Create a Triple DES cipher object in ECB mode
    cipher = DES3.new(key, DES3.MODE_ECB)
    
    # Pad the data to be a multiple of 8 bytes (DES block size)
    padded_data = pad(data, 8)
    
    # Encrypt the data
    encrypted_data = cipher.encrypt(padded_data)
    
    return encrypted_data

def decrypt_3des(key, encrypted_data):
    """
    Decrypt data that was encrypted using Triple DES.
    
    Args:
        key (bytes): The encryption key (must be 16 or 24 bytes long)
        encrypted_data (bytes): The encrypted data
        
    Returns:
        bytes: The decrypted data
    """
    # Ensure the key is the correct length (24 bytes for Triple DES)
    if len(key) == 16:
        # If key is 16 bytes, extend it to 24 bytes by appending the first 8 bytes
        key = key + key[:8]
    elif len(key) != 24:
        # If key is not 16 or 24 bytes, pad or truncate it
        key = key.ljust(24, b'\0')[:24]
    
    # Create a Triple DES cipher object in ECB mode
    cipher = DES3.new(key, DES3.MODE_ECB)
    
    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_data)
    
    # Remove the padding
    try:
        unpadded_data = unpad(decrypted_data, 8)
        return unpadded_data
    except ValueError:
        # If unpadding fails, return the decrypted data as is
        # This might happen if the original data was not properly padded
        return decrypted_data

# Example usage (for testing)
if __name__ == "__main__":
    key = b"thisisasecretkey"  # 16 bytes key
    data = b"Hello, Triple DES!"
    
    encrypted = encrypt_3des(key, data)
    print("Encrypted:", encrypted.hex())
    
    decrypted = decrypt_3des(key, encrypted)
    print("Decrypted:", decrypted.decode())