import base64
import hashlib
import os
import uuid
from io import BytesIO

from PIL import Image
import numpy as np
from flask import Flask, url_for, render_template, request, redirect, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode
text_seperator = '\x1E'

app = Flask(__name__,template_folder='templates')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)

migrate = Migrate(app,db)

class EncryptedData(db.Model):
    id = db.Column(db.String(128), primary_key=True, default=lambda: str(uuid.uuid4()))
    salt = db.Column(db.String(64), nullable=False)
    nonce = db.Column(db.String(64), nullable=False)
    tag = db.Column(db.String(64), nullable=False)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt',methods=['GET','POST'])
def encode_image():
    if request.method == 'GET':
        return render_template('encode_image.html')

    if request.method == 'POST':
        file = request.files['image']

        PilImage = Image.open(file).convert('RGB')
        ImgArr = np.array(PilImage)

        key = request.form.get('key')
        message = request.form.get('message')
        message_hash = hashlib.sha512(message.encode()).hexdigest()

        salt,nonce,cipher_text,tag = encrypt(message,key)

        encryption_data = EncryptedData(salt=salt,nonce=nonce,tag=tag)
        db.session.add(encryption_data)
        db.session.commit()
        data_id = encryption_data.id


        encode_text = text_seperator+message_hash+text_seperator + cipher_text +text_seperator+b64encode(str(data_id).encode()).decode()+text_seperator
        binary_encode_text = ''.join(format(ord(c), '08b') for c in encode_text)

        flat_img_arr = ImgArr.ravel()

        if len(flat_img_arr) < len(binary_encode_text):
            raise ValueError("message is too long for image try selecting another image or consider shortening the message.")

        for i in range(len(binary_encode_text)):
            flat_img_arr[i] = (flat_img_arr[i] & 254) | int(binary_encode_text[i])

        encoded_img_arr = flat_img_arr.reshape(ImgArr.shape)
        encoded_img = Image.fromarray(encoded_img_arr.astype(np.uint8))

        img_io = BytesIO()  # this file like object is required to send file to user without saving locally
        encoded_img.save(img_io,format="PNG")
        img_io.seek(0)      # move cursor to beginning so further read operations go smoothly and sending

        return send_file(img_io, mimetype='image/png', as_attachment=True, download_name="image.png")

@app.route('/decrypt')
def decode_image():
    return ""


def encrypt(message: str, password: str) -> tuple:
    salt = os.urandom(16)  # Generate a 16-byte salt
    key = derive_key(password, salt)  # Generate AES-256 key
    nonce = os.urandom(12)  # Generate a 12-byte nonce (random IV)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))  # AES-GCM cipher object
    encryptor = cipher.encryptor()  # Create encryptor
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()  # Encrypt message

    return (b64encode(salt).decode(),  # Convert salt to a storable string
            b64encode(nonce).decode(),  # Convert nonce to a storable string
            b64encode(ciphertext).decode(),  # Convert encrypted message
            b64encode(encryptor.tag).decode())  # Authentication tag (ensures data integrity)


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Hashing algorithm for key derivation
        length=32,  # AES-256 requires a 32-byte key
        salt=salt,  # Unique salt for randomness
        iterations=100000,  # Slows down brute-force attacks
    )
    return kdf.derive(password.encode())  # Generate and return the key


if __name__ == '__main__':
    app.run('0.0.0.0',debug=True)