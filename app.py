
from flask import Flask, request, jsonify, render_template,url_for
from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import base64
import time

app = Flask(__name__)

class AESCipher:
    def __init__(self):
        self.block_size = AES.block_size
        self.encryption_key = None
        self.decryption_key = None
        self.encryption_expiry = None

    def generate_key(self, key_size):
        return Random.get_random_bytes(key_size)

    def set_encryption_key(self, key, duration=None):
        self.encryption_key = hashlib.sha256(key).digest()
        self.encryption_expiry = time.time() + duration * 60 if duration else None
        self.decryption_key = self.encryption_key  # Use the same key for decryption

    def encrypt(self, plain_text):
        if not self.encryption_key:
            raise ValueError("Encryption key is not set")
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return base64.b64encode(iv + encrypted_text).decode('utf-8')

    def decrypt(self, encrypted_text):
        if not self.decryption_key:
            raise ValueError("Decryption key is not set")
        if self.encryption_expiry and time.time() > self.encryption_expiry:
            raise ValueError("Encryption key has expired")
        try:
            encrypted_text = base64.b64decode(encrypted_text)
            iv = encrypted_text[:self.block_size]
            cipher = AES.new(self.decryption_key, AES.MODE_CBC, iv)
            plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode('utf-8')
            return self.__unpad(plain_text)
        except ValueError as e:
            raise ValueError("Incorrect decryption key or ciphertext")

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        return plain_text + padding_str

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[-1]
        return plain_text[:-ord(last_character)]

cipher = AESCipher()

""" @app.route('/')
def index():
    return render_template('index.html')   """
@app.route('/')
def index():
    return render_template('app.html')
""" @app.route('/about')
def index():
    return render_template('about.html') 
@app.route('/contact')
def index():
    return render_template('contact.html')  """

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.get_json()
        key_size = int(data.get('key_size', 32))  # Default key size is 32 bytes (256 bits)
        duration = int(data.get('duration', 5))  # Default duration is 5 minutes
        key = cipher.generate_key(key_size)
        plain_text = data['plain_text']
        
        cipher.set_encryption_key(key, duration=duration)
        encrypted_text = cipher.encrypt(plain_text)
        
        return jsonify({'ciphertext': encrypted_text, 'key': base64.b64encode(key).decode('utf-8'), 'expiry_time': cipher.encryption_expiry})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()
        key = base64.b64decode(data['key'])
        encrypted_text = data['ciphertext']
        
        cipher.decryption_key = hashlib.sha256(key).digest()
        decrypted_text = cipher.decrypt(encrypted_text)
        
        return jsonify({'plaintext': decrypted_text})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
