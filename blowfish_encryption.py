import struct

# Constants for Blowfish
P_ARRAY = [
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B
]

# Simplified S-Boxes (Normally, Blowfish has 4 large S-Boxes)
S_BOX = [[i for i in range(256)] for _ in range(4)]

def F(x):
    """Blowfish F function (substitution-permutation)"""
    d = x & 0xFF
    c = (x >> 8) & 0xFF
    b = (x >> 16) & 0xFF
    a = (x >> 24) & 0xFF
    return ((S_BOX[0][a] + S_BOX[1][b]) ^ S_BOX[2][c]) + S_BOX[3][d]

def encrypt_block(left, right):
    """Encrypts a 64-bit block (32-bit left, 32-bit right)"""
    for i in range(16):
        left ^= P_ARRAY[i]
        right ^= F(left)
        left, right = right, left  # Swap
    left, right = right, left  # Final swap
    right ^= P_ARRAY[16]
    left ^= P_ARRAY[17]
    return left, right

def decrypt_block(left, right):
    """Decrypts a 64-bit block (32-bit left, 32-bit right)"""
    for i in range(17, 1, -1):
        left ^= P_ARRAY[i]
        right ^= F(left)
        left, right = right, left  # Swap
    left, right = right, left  # Final swap
    right ^= P_ARRAY[1]
    left ^= P_ARRAY[0]
    return left, right

def pad_data(data):
    """Pads data to be a multiple of 8 bytes (64-bit)"""
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)

def unpad_data(data):
    """Removes padding from decrypted data"""
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_blowfish(key, data):
    """Encrypt data with Blowfish algorithm"""
    data = pad_data(data)
    encrypted = bytearray()
    for i in range(0, len(data), 8):
        left, right = struct.unpack('>II', data[i:i+8])
        left, right = encrypt_block(left, right)
        encrypted.extend(struct.pack('>II', left, right))
    return encrypted

def decrypt_blowfish(key, encrypted):
    """Decrypt Blowfish encrypted data"""
    decrypted = bytearray()
    for i in range(0, len(encrypted), 8):
        left, right = struct.unpack('>II', encrypted[i:i+8])
        left, right = decrypt_block(left, right)
        decrypted.extend(struct.pack('>II', left, right))
    return unpad_data(decrypted)

if __name__ == "__main__":
    key = b"testkey123"  # Blowfish requires a key (normally 32-448 bits)
    data = b"Hello, Blowfish!"

    encrypted = encrypt_blowfish(key, data)
    print("Encrypted:", encrypted.hex())

    decrypted = decrypt_blowfish(key, encrypted)
    print("Decrypted:", decrypted.decode())
