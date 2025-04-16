import os
import time
import base64
import uuid
import json
import hashlib
import socket
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, send_file, flash, redirect, url_for, jsonify, after_this_request, session
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import qrcode

# --- Setup ---
app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'uploads'
QR_FOLDER = 'static/qrcodes'
TEMP_FOLDER = 'temp_encrypted'
METADATA_FOLDER = 'metadata'

for folder in [UPLOAD_FOLDER, QR_FOLDER, TEMP_FOLDER, METADATA_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# --- Utilities ---
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_file_hash(data):
    return hashlib.sha256(data).hexdigest()

def encrypt_data(data, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    return encrypted, salt

def decrypt_data(data, password, salt):
    key = generate_key(password, salt)
    fernet = Fernet(key)
    try:
        return fernet.decrypt(data)
    except:
        return None

def save_metadata(file_id, metadata):
    with open(os.path.join(METADATA_FOLDER, f"{file_id}.json"), 'w') as f:
        json.dump(metadata, f)

def load_metadata(file_id):
    try:
        with open(os.path.join(METADATA_FOLDER, f"{file_id}.json"), 'r') as f:
            return json.load(f)
    except:
        return None

def send_otp(email, otp):
    # Send OTP to user's email
    sender_email = "bhaleraopratik911202@gmail.com"  # Use your email
    sender_password = "Pratik@2002"  # Use your email password
    receiver_email = email

    subject = "Your OTP for file download"
    body = f"Your OTP for downloading the file is: {otp}"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()
    except Exception as e:
        print(f"Error sending email: {e}")

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    password = request.form['password']
    file = request.files['file']
    recipient_email = request.form['email']

    if len(password) < 8:
        flash("Password must be at least 8 characters long.")
        return redirect(url_for('index'))

    if file:
        filename = secure_filename(file.filename)
        if ".." in filename or "/" in filename or "\\" in filename:
            flash("Invalid file name.")
            return redirect(url_for('index'))

        data = file.read()
        encrypted, salt = encrypt_data(data, password)

        file_id = str(uuid.uuid4())
        access_token = str(uuid.uuid4())
        encrypted_filename = file_id + "_" + filename
        encrypted_path = os.path.join(TEMP_FOLDER, encrypted_filename)

        with open(encrypted_path, 'wb') as f:
            f.write(encrypted)

        timestamp = time.time()
        metadata = {
            "filename": filename,
            "timestamp": timestamp,
            "downloaded": False,
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "password_hash": hash_password(password),
            "token": access_token,
            "file_hash": get_file_hash(data),
            "recipient_email": recipient_email,
            "otp": None,  # OTP will be set here
            "otp_expiry": None  # OTP expiry time will be set here
        }
        save_metadata(file_id, metadata)

        local_ip = get_local_ip()
        download_url = f'http://{local_ip}:5000/download/{file_id}?filename={filename}&token={access_token}'

        qr = qrcode.make(download_url)
        qr_filename = file_id + '_qr.png'
        qr_path = os.path.join(QR_FOLDER, qr_filename)
        qr.save(qr_path)

        return render_template('result.html', qr_filename=qr_filename, message="Scan the QR and enter email + password to download.", file_id=file_id, created_at=timestamp)

    flash("Something went wrong.")
    return redirect(url_for('index'))

@app.route('/download/<file_id>', methods=['GET', 'POST'])
def download(file_id):
    filename = request.args.get('filename')
    token = request.args.get('token')
    encrypted_filename = file_id + "_" + filename
    file_path = os.path.join(TEMP_FOLDER, encrypted_filename)

    metadata = load_metadata(file_id)
    if not metadata:
        flash("Invalid or expired link.")
        return redirect(url_for('index'))

    if metadata.get("token") != token:
        flash("Unauthorized access.")
        return redirect(url_for('index'))

    time_diff = time.time() - metadata["timestamp"]
    if time_diff > 120:
        if os.path.exists(file_path):
            os.remove(file_path)
        meta_path = os.path.join(METADATA_FOLDER, f"{file_id}.json")
        if os.path.exists(meta_path):
            os.remove(meta_path)
        flash("⏰ Link has expired. Please re-upload the file.")
        return redirect(url_for('index'))

    if metadata.get("downloaded"):
        flash("This file has already been downloaded.")
        return redirect(url_for('index'))

    if request.method == 'POST':
        step = request.form.get('step')

        if step == 'verify_email':
            entered_email = request.form.get('email')
            if entered_email != metadata['recipient_email']:
                flash("❌ Email does not match. Access denied.")
                return render_template('download.html', file_id=file_id, filename=filename, email_verified=False)

            otp = str(random.randint(100000, 999999))  # Generate OTP
            metadata['otp'] = otp
            metadata['otp_expiry'] = time.time() + 300  # OTP expires in 5 minutes
            save_metadata(file_id, metadata)

            # Send OTP to the recipient's email
            send_otp(entered_email, otp)

            session['email_verified'] = True
            return render_template('download.html', file_id=file_id, filename=filename, email_verified=True)

        elif step == 'verify_otp':
            entered_otp = request.form.get('otp')
            if entered_otp != metadata['otp']:
                flash("❌ Incorrect OTP. Access denied.")
                return render_template('download.html', file_id=file_id, filename=filename, email_verified=True)

            if time.time() > metadata['otp_expiry']:
                flash("❌ OTP has expired.")
                return render_template('download.html', file_id=file_id, filename=filename, email_verified=True)

            return render_template('download.html', file_id=file_id, filename=filename, otp_verified=True)

        elif step == 'decrypt_and_download':
            if not session.get('email_verified'):
                flash("Please verify email first.")
                return render_template('download.html', file_id=file_id, filename=filename, email_verified=False)

            password = request.form['password']

            if hash_password(password) != metadata.get("password_hash"):
                flash("Incorrect password.")
                return render_template('download.html', file_id=file_id, filename=filename, email_verified=True)

            if not os.path.exists(file_path):
                flash("File not found or already downloaded.")
                return redirect(url_for('index'))

            with open(file_path, 'rb') as f:
                encrypted = f.read()

            salt = base64.urlsafe_b64decode(metadata['salt'].encode())
            decrypted = decrypt_data(encrypted, password, salt)

            if decrypted is None:
                flash("Incorrect password or corrupted file.")
                return render_template('download.html', file_id=file_id, filename=filename, email_verified=True)

            if get_file_hash(decrypted) != metadata.get("file_hash"):
                flash("File integrity check failed.")
                return render_template('download.html', file_id=file_id, filename=filename, email_verified=True)

            decrypted_path = os.path.join(UPLOAD_FOLDER, filename)
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted)

            os.remove(file_path)
            metadata['downloaded'] = True
            save_metadata(file_id, metadata)

            @after_this_request
            def remove_file(response):
                try:
                    os.remove(decrypted_path)
                except:
                    pass
                return response

            return send_file(decrypted_path, as_attachment=True)

    return render_template('download.html', file_id=file_id, filename=filename, email_verified=False)

@app.route('/check_download/<file_id>')
def check_download(file_id):
    metadata = load_metadata(file_id)
    if metadata:
        expired = (time.time() - metadata["timestamp"]) > 120
        return jsonify({"downloaded": metadata.get("downloaded", False), "expired": expired})
    return jsonify({"downloaded": False, "expired": True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
