from flask import Flask, request, render_template, send_file, jsonify, redirect, url_for, session
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import hashlib
import secrets
import random

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Key untuk session

# Directory to store uploads
UPLOAD_FOLDER = 'uploads'
PRIVATE_KEY_FOLDER = 'keys'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PRIVATE_KEY_FOLDER, exist_ok=True)

# Generate a new RSA key pair and save it to a file with a unique name
def generate_private_key_file():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    random_suffix = str(random.randint(10**9, 10**10 - 1))  # Generate 10-digit random number
    key_path = os.path.join(PRIVATE_KEY_FOLDER, f'private_key_{random_suffix}.pem')
    with open(key_path, 'wb') as f:
        f.write(private_pem)
    return private_key, key_path

# AES encryption helper
def aes_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

# AES decryption helper
def aes_decrypt(data, key):
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data[16:]) + decryptor.finalize()

# Hash password helper
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# RSA encryption helper
def rsa_encrypt(secret_key, public_key):
    return public_key.encrypt(
        secret_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# RSA decryption helper
def rsa_decrypt(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
# (Kode helper functions tetap sama...)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    password = request.form['password']
    secret_key = secrets.token_bytes(32)  # Generate AES key

     # Tambahkan 7 digit kode random ke nama file
    random_suffix = ''.join(random.choices('0123456789abcdefghijklmnopqrstuvwxyzQWERTYUIOPLKJHGFDSAZXCVBNM', k=7))
    filename, file_extension = os.path.splitext(file.filename)
    new_filename = f"{filename}{random_suffix}{file_extension}"
    encrypted_path = os.path.join(UPLOAD_FOLDER, new_filename)

    # Encrypt the file
    encrypted_data = aes_encrypt(file.read(), secret_key)

    # Save encrypted file
     # Save encrypted file with the new filename
    encrypted_path = os.path.join(UPLOAD_FOLDER, new_filename)  # Use new_filename
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)

    # Generate RSA key pair for the file
    private_key, private_key_path = generate_private_key_file()
    public_key = private_key.public_key()

    # Encrypt the AES key with the RSA public key
    encrypted_secret_key = rsa_encrypt(secret_key, public_key)

    # Save encrypted secret key and hashed password
    hashed_password = hash_password(password)
    secret_key_path = os.path.join(UPLOAD_FOLDER, f'{new_filename}.key')
    with open(secret_key_path, 'wb') as f:
        f.write(encrypted_secret_key + b'\n' + hashed_password.encode('utf-8'))

    # Simpan informasi file di session
    session['private_key_path'] = private_key_path
    session['new_filename'] = new_filename

    # Redirect ke halaman sukses
    return redirect(url_for('success'))

@app.route('/success')
def success():
    if 'private_key_path' not in session:
        return redirect(url_for('index'))  # Jika tidak ada data di session, kembali ke index
    return render_template('success.html', new_filename=session['new_filename'])

@app.route('/download_key', methods=['POST'])
def download_key():
    if 'private_key_path' not in session:
        return redirect(url_for('index'))
    private_key_path = session.pop('private_key_path', None)  # Hapus dari session setelah download
    if private_key_path and os.path.exists(private_key_path):
        return send_file(private_key_path, as_attachment=True)
    return "File private key tidak ditemukan.", 404

@app.route('/download', methods=['POST'])
def download_file():
    filename = request.form['filename']
    password = request.form['password']
    private_key_file = request.files['private_key']

    try:
        # Load private key hanya sekali
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None
        )

        # Hash password
        hashed_password = hash_password(password)

        # Load encrypted secret key and hashed password
        secret_key_path = os.path.join(UPLOAD_FOLDER, f'{filename}.key')
        with open(secret_key_path, 'rb') as f:
            key_data = f.read().split(b'\n', 1)

        if len(key_data) != 2:
            return render_template('gagal.html', error="Invalid key file format")

        encrypted_secret_key = key_data[0]
        stored_hashed_password = key_data[1].decode('utf-8')

        # Verify password
        if hashed_password != stored_hashed_password:
            return render_template('gagal.html', error="Incorrect password")

        # Decrypt secret key
        secret_key = rsa_decrypt(encrypted_secret_key, private_key)

        # Load and decrypt the file
        encrypted_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = aes_decrypt(encrypted_data, secret_key)

        # Send the decrypted file directly to the user without saving
        return (
            decrypted_data,
            200,
            {
                'Content-Type': 'application/octet-stream',
                'Content-Disposition': f'attachment; filename="decrypted_{filename}"'
            }
        )

    except UnicodeDecodeError:
        return render_template('gagal.html', error="Failed to decode password or key file.")
    except Exception as e:
        # Log the error for debugging purposes
        print(f"Error during decryption: {str(e)}")
        return render_template('gagal.html', error=f"An error occurred: {str(e)}")

if __name__ == '__main__':
    app.run(debug=True)