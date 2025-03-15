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

message_start = '\x02'
message_end = '\x03'
parts_seperator = '\x1E'

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

        encode_text = message_start + parts_seperator + message_hash + parts_seperator + cipher_text + parts_seperator + data_id + parts_seperator + message_end
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

@app.route('/decrypt',methods=['GET','POST'])
def decode_image():
    if request.method == 'GET':
        return render_template('decode_image.html')
    elif request.method == 'POST':

        image_file = request.files['image']
        user_key = request.form.get('key')

        PilImage = Image.open(image_file).convert('RGB')
        ImgArr = np.array(PilImage)

        flatImgArr = ImgArr.ravel()

        lsb_Arr = []

        for i in flatImgArr:
            if i & 1:
                lsb_Arr.append(1)
            else:
                lsb_Arr.append(0)

        print(lsb_Arr)

        text_bytes = bytearray()
        current_byte = 0
        bit_count = 0
        reading = False

        for i in lsb_Arr:
            current_byte = (current_byte << 1) | i
            bit_count += 1

            if bit_count == 8:
                if current_byte == ord(message_start):
                    reading = True
                    bit_count = 0
                    current_byte = 0
                    continue

                if current_byte == ord(message_end):
                    break

                if reading:
                    text_bytes.append(current_byte)
                    bit_count = 0
                    current_byte = 0


        hidden_text = text_bytes.decode('utf-8')
        hidden_text_parts = hidden_text.split(parts_seperator)

        cipher_text_hash = hidden_text_parts[1]
        cipher_text = hidden_text_parts[2]
        cipher_text_id = hidden_text_parts[3]

        data = EncryptedData.query.filter(EncryptedData.id == cipher_text_id).first()
        salt = data.salt
        nonce = data.nonce
        tag = data.tag

        decoded_text = decrypt(cipher_text = cipher_text,salt=salt,nonce=nonce,tag=tag,password=user_key)

        return render_template('download.html',decrypted_message = decoded_text)


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

def decrypt(cipher_text: str,salt: str,nonce: str,tag: str,password: str) -> str:
    Salt = b64decode(salt)
    Nonce = b64decode(nonce)
    Tag = b64decode(tag)
    Cipher_text = b64decode(cipher_text)

    key = derive_key(password=password,salt=Salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(Nonce, Tag))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(Cipher_text) + decryptor.finalize()

    return decrypted_message.decode()


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