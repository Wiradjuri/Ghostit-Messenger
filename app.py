import os
import base64
import secrets 
import logging
from flask import Flask, request, render_template, send_file, redirect, url_for, flash, jsonify, g
from flask_wtf import FlaskForm 
from wtforms import StringField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length
from flask_wtf.file import FileField, FileAllowed
from flask_wtf.csrf import CSRFProtect
from Cryptodome.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
load_dotenv()
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import psycopg2
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from flask_bcrypt import Bcrypt
import vonage
from werkzeug.utils import secure_filename
import tempfile
import atexit
from datetime import datetime, timedelta
import shutil

app = Flask(__name__)
load_dotenv()

VONAGE_API_KEY = os.getenv("VONAGE_API_KEY")
VONAGE_API_SECRET = os.getenv("VONAGE_API_SECRET")
VONAGE_BRAND_NAME = "Brand Name"
TO_NUMBER = os.getenv("TO_NUMBER")
client = vonage.Client(key=VONAGE_API_KEY, secret=VONAGE_API_SECRET)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'workspace')
app.config['DECRYPTED_FILES_FOLDER'] = os.path.join(os.getcwd(), 'decrypted_files')

# Ensure the upload and decrypted files folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DECRYPTED_FILES_FOLDER'], exist_ok=True)

csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Logger setup
logging.basicConfig(level=logging.INFO)

def create_tables():
    try:
        postgres_url_main = os.getenv('DATABASE_URL')
        conn_main = psycopg2.connect(postgres_url_main)
        cur_main = conn_main.cursor()
        cur_main.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            message TEXT,
            sender_username VARCHAR(255) NOT NULL,
            receiver_username VARCHAR(255) NOT NULL,
            public_key TEXT NOT NULL,
            encrypted_image BYTEA
        );
        """)
        cur_main.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(60) NOT NULL,
            is_verified BOOLEAN DEFAULT TRUE
        );
        """)
        conn_main.commit()
        cur_main.close()
        conn_main.close()

        postgres_url_send = os.getenv('DATABASE_URL_SEND')
        conn_send = psycopg2.connect(postgres_url_send)
        cur_send = conn_send.cursor()
        cur_send.execute("""
        CREATE TABLE IF NOT EXISTS privatekeys (
            id SERIAL PRIMARY KEY,
            sender_username VARCHAR(255) NOT NULL,
            receiver_username VARCHAR(255) NOT NULL,
            encrypted_private_key TEXT NOT NULL
        );
        """)
        cur_send.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_images (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            encrypted_image BYTEA NOT NULL,
            encrypted_key BYTEA NOT NULL,
            filename VARCHAR(255) NOT NULL
        );
        """)
        conn_send.commit()
        cur_send.close()
        conn_send.close()
    except psycopg2.Error as e:
        app.logger.error(f"PostgreSQL Error: {str(e)}")
    except Exception as e:
        app.logger.error(f"General Error: {str(e)}")

create_tables()


class User(UserMixin):
    def __init__(self, id, username, password_hash, is_verified):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_verified = is_verified

@login_manager.user_loader
def load_user(user_id):
    try:
        postgres_url_main = os.getenv('DATABASE_URL')
        conn_main = psycopg2.connect(postgres_url_main)
        cur_main = conn_main.cursor()
        cur_main.execute("SELECT id, username, password_hash, is_verified FROM users WHERE id = %s", (user_id,))
        user = cur_main.fetchone()
        cur_main.close()
        conn_main.close()
        if user:
            return User(id=user[0], username=user[1], password_hash=user[2], is_verified=user[3])
    except psycopg2.Error as e:
        app.logger.error(f"PostgreSQL Error: {str(e)}")
    except Exception as e:
        app.logger.error(f"General Error: {str(e)}")
    return None

class MessageForm(FlaskForm):
    sender = StringField('Sender', validators=[DataRequired(), Length(max=255)])
    receiver = StringField('Receiver', validators=[DataRequired(), Length(max=255)])
    message = TextAreaField('Message', validators=[Length(max=5000)])
    file = FileField('File', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'pdf', 'docx', 'txt', 'zip', 'rar', 'apk', 'mp4', 'mp3', 'wav', 'webp'], 'Allowed file types are images and documents.')])
    private_key_password = PasswordField('Private Key Password', validators=[DataRequired()])
    phone_number = StringField('Phone Number')
    submit = SubmitField('Send')


class DecryptForm(FlaskForm):
    receiver = StringField('Receiver', validators=[DataRequired(), Length(max=255)])
    private_key_password = PasswordField('Private Key Password', validators=[DataRequired()])
    submit = SubmitField('Decrypt')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=255)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')

def generate_keys():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    return private_key, public_key

def encrypt_data(public_key, data):
    try:
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted = cipher_rsa.encrypt(data)
        return base64.b64encode(encrypted)
    except Exception as e:
        app.logger.error(f"Encryption failed: {str(e)}")
        raise

def decrypt_data(private_key, encrypted_data):
    try:
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted = cipher_rsa.decrypt(base64.b64decode(encrypted_data))
        return decrypted
    except Exception as e:
        app.logger.error(f"Decryption failed: {str(e)}")
        raise

def generate_symmetric_key():
    return Fernet.generate_key()

def encrypt_image(image_data, key):
    cipher = Fernet(key)
    return cipher.encrypt(image_data)

def encrypt_symmetric_key(symmetric_key, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(symmetric_key)

def save_to_database(username, encrypted_image, encrypted_key, filename):
    postgres_url_send = os.getenv('DATABASE_URL_SEND')
    conn_send = psycopg2.connect(postgres_url_send)
    cur_send = conn_send.cursor()
    app.logger.info(f"Saving encrypted image for {username} with filename {filename}")
    cur_send.execute('''
    INSERT INTO encrypted_images (username, encrypted_image, encrypted_key, filename)
    VALUES (%s, %s, %s, %s)
    ''', (username, encrypted_image, encrypted_key, filename))
    conn_send.commit()
    cur_send.close()
    conn_send.close()



def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_private_key(private_key_pem: str, password: str) -> str:
    try:
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        fernet = Fernet(key)
        encrypted_private_key = fernet.encrypt(private_key_pem.encode('utf-8'))
        return base64.urlsafe_b64encode(salt + encrypted_private_key).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting private key: {str(e)}")
        raise

def decrypt_private_key(encrypted_private_key: str, password: str) -> str:
    try:
        decoded_data = base64.urlsafe_b64decode(encrypted_private_key)
        salt, encrypted_private_key = decoded_data[:16], decoded_data[16:]
        key = derive_key(password, salt)
        fernet = Fernet(key)
        private_key_pem = fernet.decrypt(encrypted_private_key).decode('utf-8')
        return private_key_pem
    except Exception as e:
        app.logger.error(f"Wrong Password or Decryption Error: {str(e)}")
        raise

def delete_private_key_from_database(sender, receiver):
    try:
        postgres_url_send = os.getenv('DATABASE_URL_SEND')
        conn_send = psycopg2.connect(postgres_url_send)
        cur_send = conn_send.cursor()
        cur_send.execute("DELETE FROM privatekeys WHERE sender_username = %s AND receiver_username = %s", (sender, receiver))
        conn_send.commit()
        cur_send.close()
        conn_send.close()
    except psycopg2.Error as e:
        app.logger.error(f"PostgreSQL Error during deletion: {str(e)}")
        raise
    except Exception as e:
        app.logger.error(f"General Error during deletion: {str(e)}")
        raise

def delete_encrypted_image_from_database(receiver, encrypted_image):
    try:
        postgres_url_send = os.getenv('DATABASE_URL_SEND')
        conn_send = psycopg2.connect(postgres_url_send)
        cur_send = conn_send.cursor()
        cur_send.execute("DELETE FROM encrypted_images WHERE username = %s AND encrypted_image = %s", (receiver, encrypted_image))
        conn_send.commit()
        cur_send.close()
        conn_send.close()
    except psycopg2.Error as e:
        app.logger.error(f"PostgreSQL Error during deletion: {str(e)}")
        raise
    except Exception as e:
        app.logger.error(f"General Error during deletion: {str(e)}")
        raise

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        postgres_url_main = os.getenv('DATABASE_URL')
        conn_main = psycopg2.connect(postgres_url_main)
        cur_main = conn_main.cursor()
        try:
            cur_main.execute("INSERT INTO users (username, password_hash, is_verified) VALUES (%s, %s, %s)", (username, password_hash, True))
            conn_main.commit()
            return redirect(url_for('login'))
        except psycopg2.Error as e:
            flash('Username already exists. Please choose a different username.', 'error')
        finally:
            cur_main.close()
            conn_main.close()

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        postgres_url_main = os.getenv('DATABASE_URL')
        conn_main = psycopg2.connect(postgres_url_main)
        cur_main = conn_main.cursor()
        cur_main.execute("SELECT id, username, password_hash, is_verified FROM users WHERE username = %s", (username,))
        user = cur_main.fetchone()
        cur_main.close()
        conn_main.close()

        if user and bcrypt.check_password_hash(user[2], password):
            if user[3]:
                user_obj = User(id=user[0], username=user[1], password_hash=user[2], is_verified=user[3])
                login_user(user_obj)
                return redirect(url_for('home'))
            else:
                flash('')
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def decrypt_image_and_key(private_key, encrypted_image, encrypted_key):
    try:
        app.logger.info("Starting decryption of the image and key")
        cipher_rsa = PKCS1_OAEP.new(private_key)
        
        # Check if encrypted_key is bytes
        if not isinstance(encrypted_key, bytes):
            if isinstance(encrypted_key, memoryview):
                encrypted_key = encrypted_key.tobytes()
            else:
                app.logger.error(f"Encrypted key is not bytes: {type(encrypted_key)}")
                raise ValueError("Encrypted key must be bytes")
        
        symmetric_key = cipher_rsa.decrypt(encrypted_key)
        app.logger.info("Symmetric key decrypted successfully")

        # Check if encrypted_image is bytes
        if not isinstance(encrypted_image, bytes):
            if isinstance(encrypted_image, memoryview):
                encrypted_image = encrypted_image.tobytes()
            else:
                app.logger.error(f"Encrypted image is not bytes: {type(encrypted_image)}")
                raise ValueError("Encrypted image must be bytes")

        cipher = Fernet(symmetric_key)
        decrypted_image = cipher.decrypt(encrypted_image)
        app.logger.info("Image decrypted successfully")
        
        return decrypted_image
    except Exception as e:
        app.logger.error(f"Error decrypting image and key: {str(e)}")
        raise

@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if not current_user.is_verified:
        return redirect(url_for('logout'))

    message_form = MessageForm()
    decrypt_form = DecryptForm()
    decrypted_messages = []

    if message_form.validate_on_submit() and message_form.submit.data:
        try:
            sender = message_form.sender.data
            receiver = message_form.receiver.data
            message = message_form.message.data
            file = message_form.file.data
            private_key_password = message_form.private_key_password.data
            phone_number = message_form.phone_number.data

            if phone_number and phone_number.startswith('04'):
                phone_number = '61' + phone_number[1:]

            if file and file.content_length > 20 * 1024 * 1024:
                flash('File size should not exceed 20MB.', 'error')
                return redirect(url_for('home'))

            private_key, public_key = generate_keys()
            encrypted_message_base64 = encrypt_data(public_key, message.encode()) if message else None

            encrypted_file = None
            if file:
                filename = secure_filename(file.filename)
                file_data = file.read()
                symmetric_key = generate_symmetric_key()
                encrypted_file = encrypt_image(file_data, symmetric_key)
                encrypted_key = encrypt_symmetric_key(symmetric_key, public_key)
                save_to_database(receiver, encrypted_file, encrypted_key, filename)

            pem_private_key = private_key.export_key().decode()
            pem_public_key = public_key.export_key().decode()

            encrypted_private_key = encrypt_private_key(pem_private_key, private_key_password)

            postgres_url_main = os.getenv('DATABASE_URL')
            conn_main = psycopg2.connect(postgres_url_main)
            cur_main = conn_main.cursor()
            cur_main.execute("""
                INSERT INTO messages (message, sender_username, receiver_username, public_key, encrypted_image)
                VALUES (%s, %s, %s, %s, %s)
            """, (encrypted_message_base64.decode() if encrypted_message_base64 else None, sender, receiver, pem_public_key, encrypted_file))
            conn_main.commit()
            cur_main.close()
            conn_main.close()

            postgres_url_send = os.getenv('DATABASE_URL_SEND')
            conn_send = psycopg2.connect(postgres_url_send)
            cur_send = conn_send.cursor()
            cur_send.execute("""
                INSERT INTO privatekeys (sender_username, receiver_username, encrypted_private_key)
                VALUES (%s, %s, %s)
            """, (sender, receiver, encrypted_private_key))
            conn_send.commit()
            cur_send.close()
            conn_send.close()

            if phone_number:
                responseData = client.sms.send_message(
                    {
                        "from": "TempDefend",
                        "to": phone_number,
                        "text": "You've got a message on GhostIT Messenger.",
                    }
                )

                if responseData["messages"][0]["status"] == "0":
                    app.logger.info("Message sent successfully.")
                else:
                    app.logger.error(f"Message failed with error: {responseData['messages'][0]['error-text']}")

            flash('Message successfully sent', 'success')
            return redirect(url_for('home'))
        except Exception as e:
            app.logger.error(f"Error: {str(e)}")
            flash(f'An error occurred: {str(e)}', 'error')

    if decrypt_form.validate_on_submit() and decrypt_form.submit.data:
        receiver = decrypt_form.receiver.data
        private_key_password = decrypt_form.private_key_password.data

        try:
            postgres_url_main = os.getenv('DATABASE_URL')
            conn_main = psycopg2.connect(postgres_url_main)
            cur_main = conn_main.cursor()
            cur_main.execute("""
                SELECT id, message, public_key, sender_username, encrypted_image FROM messages
                WHERE receiver_username = %s
                ORDER BY id DESC
            """, (receiver,))
            results = cur_main.fetchall()
            cur_main.close()
            conn_main.close()
        except Exception as e:
            app.logger.error(f"Database connection error (main): {str(e)}")
            flash(f'An error occurred: {str(e)}', 'error')
            return render_template('home.html', message_form=message_form, decrypt_form=decrypt_form, decrypted_messages=decrypted_messages)

        try:
            postgres_url_send = os.getenv('DATABASE_URL_SEND')
            conn_send = psycopg2.connect(postgres_url_send)
            cur_send = conn_send.cursor()
            cur_send.execute("""
                SELECT id, sender_username, encrypted_private_key FROM privatekeys WHERE receiver_username = %s
            """, (receiver,))
            private_keys = cur_send.fetchall()
            cur_send.close()
            conn_send.close()
        except Exception as e:
            app.logger.error(f"Database connection error (send): {str(e)}")
            flash(f'An error occurred: {str(e)}', 'error')
            return render_template('home.html', message_form=message_form, decrypt_form=decrypt_form, decrypted_messages=decrypted_messages)

        decrypted_private_keys = []
        for pk_id, sender_username, encrypted_private_key in private_keys:
            try:
                private_key_pem = decrypt_private_key(encrypted_private_key, private_key_password)
                private_key = RSA.import_key(private_key_pem)
                decrypted_private_keys.append((pk_id, private_key))
            except Exception as e:
                app.logger.error(f"Error decrypting private key for {sender_username}: {str(e)}")

        if not decrypted_private_keys:
            flash('Error with password or file too large', 'error')
        else:
            for result in results:
                message_id, encrypted_message, public_key, sender_username, encrypted_file = result
                decrypted_message = None
                decrypted_file = None
                file_filename = None
                used_private_key_id = None

                for pk_id, private_key in decrypted_private_keys:
                    try:
                        if encrypted_message:
                            decrypted_message = decrypt_data(private_key, encrypted_message).decode()
                        if encrypted_file:
                            cur_send = psycopg2.connect(postgres_url_send).cursor()  # Ensure this cursor is initialized before use
                            cur_send.execute("SELECT encrypted_key, filename FROM encrypted_images WHERE username = %s ORDER BY id DESC LIMIT 1", (receiver,))
                            encrypted_key, filename = cur_send.fetchone()
                            if encrypted_key is None:
                                app.logger.error(f"Encrypted key not found for username: {receiver}")
                                continue
                            if isinstance(encrypted_key, memoryview):
                                encrypted_key = encrypted_key.tobytes()
                            decrypted_file = decrypt_image_and_key(private_key, encrypted_file, encrypted_key)
                            file_filename = f"decrypted_file_{message_id}_{sender_username}_{secure_filename(filename)}"
                            decrypted_file_path = os.path.join(app.config['DECRYPTED_FILES_FOLDER'], file_filename)
                            with open(decrypted_file_path, "wb") as file:
                                file.write(decrypted_file)
                            cur_send.close()
                        if decrypted_message or decrypted_file:
                            used_private_key_id = pk_id
                            break
                    except Exception as e:
                        app.logger.error(f"Failed: {str(e)}")

                if decrypted_message or decrypted_file:
                    decrypted_messages.append({
                        'sender_username': sender_username,
                        'receiver_username': receiver,
                        'message': decrypted_message,
                        'file_filename': file_filename
                    })

                    try:
                        postgres_url_main = os.getenv('DATABASE_URL')
                        conn_main = psycopg2.connect(postgres_url_main)
                        cur_main = conn_main.cursor()
                        cur_main.execute("DELETE FROM messages WHERE id = %s", (message_id,))
                        conn_main.commit()
                        cur_main.close()
                        conn_main.close()
                    except Exception as e:
                        app.logger.error(f"Error deleting message: {str(e)}")

                    if used_private_key_id:
                        try:
                            postgres_url_send = os.getenv('DATABASE_URL_SEND')
                            conn_send = psycopg2.connect(postgres_url_send)
                            cur_send = conn_send.cursor()
                            cur_send.execute("DELETE FROM privatekeys WHERE id = %s", (used_private_key_id,))
                            conn_send.commit()
                            cur_send.close()
                            conn_send.close()
                        except Exception as e:
                            app.logger.error(f"Error deleting private key: {str(e)}")

                    try:
                        delete_encrypted_image_from_database(receiver, encrypted_file)
                    except Exception as e:
                        app.logger.error(f"Error deleting encrypted image: {str(e)}")

    return render_template('home.html', message_form=message_form, decrypt_form=decrypt_form, decrypted_messages=decrypted_messages)

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    try:
        file_path = os.path.join(app.config['DECRYPTED_FILES_FOLDER'], filename)
        if not os.path.exists(file_path):
            flash('File not found.', 'error')
            return redirect(url_for('home'))
        return send_file(file_path, as_attachment=True)

    except Exception as e:
        app.logger.error(f"Error downloading file: {str(e)}")
        flash('Error downloading file.', 'error')
        return redirect(url_for('home'))

@app.before_request
def set_nonce():
    g.nonce = secrets.token_urlsafe(16)

@app.context_processor
def inject_nonce():
    return dict(nonce=g.nonce)

@app.after_request
def set_security_headers(response):
    csp = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'nonce-{nonce}'; "
        "script-src 'self' 'nonce-{nonce}';"
    ).format(nonce=g.nonce)
    response.headers['Content-Security-Policy'] = csp
    return response

def cleanup_decrypted_files():
    now = datetime.now()
    for filename in os.listdir(app.config['DECRYPTED_FILES_FOLDER']):
        file_path = os.path.join(app.config['DECRYPTED_FILES_FOLDER'], filename)
        if os.path.isfile(file_path):
            file_creation_time = datetime.fromtimestamp(os.path.getctime(file_path))
            if now - file_creation_time > timedelta(hours=1):
                os.remove(file_path)
                app.logger.info(f"Deleted old decrypted file: {filename}")

atexit.register(cleanup_decrypted_files)

if __name__ == '__main__':
    app.run(debug=False)
