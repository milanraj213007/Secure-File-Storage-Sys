from flask import Flask, request, send_file
import os
import hashlib
from aes_encryption import encrypt_aes, decrypt_aes
from blowfish_encryption import encrypt_blowfish, decrypt_blowfish
from tripledes_encryption import encrypt_3des, decrypt_3des
from flask_cors import CORS


app = Flask(__name__)
CORS(app)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# No default key - will use user-provided key
# KEY = b"thisisasecretkey"  # This line is removed

ENCRYPTION_METHODS = {
    "aes": (encrypt_aes, decrypt_aes),
    "blowfish": (encrypt_blowfish, decrypt_blowfish),
    "tripledes": (encrypt_3des, decrypt_3des)
}

def prepare_key(key_str, method):
    """
    Prepare the key for the specific encryption method.
    Different methods may require different key lengths.
    """
    key_bytes = key_str.encode('utf-8') 
    
    # Use SHA-256 to create a consistent key of appropriate length
    hashed_key = hashlib.sha256(key_bytes).digest()
    
    if method == "aes":
        return hashed_key[:16]  # AES-128 needs 16 bytes
    elif method == "blowfish":
        return hashed_key[:32]  # Blowfish can use up to 56 bytes, but 32 is good
    elif method == "tripledes":
        return hashed_key[:24]  # Triple DES needs 24 bytes
    
    return hashed_key  # Default

@app.route("/encrypt", methods=["POST"])
def encrypt_file():
    if "file" not in request.files or "method" not in request.form or "key" not in request.form:
        return "No file, method, or key provided", 400
    
    file = request.files["file"]
    method = request.form["method"]
    user_key = request.form["key"]

    if method not in ENCRYPTION_METHODS:
        return "Invalid encryption method", 400

    encrypt_func, _ = ENCRYPTION_METHODS[method]

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    
    with open(filepath, "rb") as f:
        data = f.read()
    
    # Prepare the key for the specific encryption method
    key = prepare_key(user_key, method)
    
    encrypted_data = encrypt_func(key, data)
    encrypted_path = filepath + ".enc"
    
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)
    
    return send_file(encrypted_path, as_attachment=True)

@app.route("/decrypt", methods=["POST"])
def decrypt_file():
    if "file" not in request.files or "method" not in request.form or "key" not in request.form:
        return "No file, method, or key provided", 400
    
    file = request.files["file"]
    method = request.form["method"]
    user_key = request.form["key"]

    if method not in ENCRYPTION_METHODS:
        return "Invalid encryption method", 400

    _, decrypt_func = ENCRYPTION_METHODS[method]

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    
    with open(filepath, "rb") as f:
        data = f.read()
    
    # Prepare the key for the specific encryption method
    key = prepare_key(user_key, method)
    
    try:
        decrypted_data = decrypt_func(key, data)
        decrypted_path = filepath.replace(".enc", "") if filepath.endswith(".enc") else filepath + ".decrypted"

        with open(decrypted_path, "wb") as f:
            f.write(decrypted_data)
        
        return send_file(decrypted_path, as_attachment=True)
    except Exception as e:
        return f"Decryption error: Possibly incorrect key or corrupted file. Error: {str(e)}", 400

if __name__ == "__main__":
    app.run(debug=True)