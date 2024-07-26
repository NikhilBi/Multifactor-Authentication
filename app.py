from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Boolean
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from io import BytesIO
import base64
import re
import smtplib
from email.mime.text import MIMEText
import secrets
from flask import session
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost:3306/app'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEBUG'] = False  # Disable debug mode
app.secret_key = 'your_secret_key'
db = SQLAlchemy(app)

# Regular expression pattern for a strong password (at least 8 characters, including uppercase, lowercase, digit, and special character)
password_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')

# Regular expression pattern for email validation
email_pattern = re.compile(r'^[\w\.-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

def generate_qrcode(username):
    # Load the TOTP secret for the user
    user = User.query.filter_by(username=username).first()
    if user is None:
        return None

    # Generate the TOTP URI
    totp_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(username, issuer_name="YourApp")

    # Generate the QR code image
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(totp_uri)
    qr.make(fit=True)

    # Create a BytesIO object to store the image data
    img_buffer = BytesIO()
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img.save(img_buffer, format="PNG")

    # Convert the image data to base64
    img_data = img_buffer.getvalue()
    base64_img = base64.b64encode(img_data).decode("utf-8")

    # Return the base64-encoded image data
    return base64_img

def validate_input(input_data):
    # Define a regular expression for allowed characters (whitelist)
    allowed_pattern = re.compile(r'^[a-zA-Z0-9_-]+$')

    # Validate against the whitelist
    return bool(allowed_pattern.match(input_data))

def generate_email_verification_code():
    # Generate a unique verification code
    return secrets.token_hex(6)  # Generate a random 6-digit hexadecimal code

def send_email_verification(email, verification_code):
    # Configure email server settings
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    sender_email = 'nikhilbiradar882@gmail.com'  # Update with your email
    sender_password = 'ubqq sfwn kxli bivx'  # Update with your email password

    # Create email message
    message = MIMEText(f'Your email verification code is: {verification_code}')
    message['Subject'] = 'Email Verification Code'
    message['From'] = sender_email
    message['To'] = email  # Use the provided email address

    # Connect to SMTP server and send email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(message)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email_verified = db.Column(Boolean)  # Make sure this matches the column in your database
    otp_secret = db.Column(db.String(16), nullable=False)

    def __init__(self, username, email, email_verified=False, otp_secret=None, password_hash=None):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.email_verified = email_verified
        self.otp_secret = otp_secret

    def __repr__(self):
        return f"<User(id={self.id}, username={self.username}, email={self.email}, email_verified={self.email_verified}, otp_secret={self.otp_secret}, password_hash={self.password_hash})>"

# Dummy database to simulate user data
users = {
    'Nikhil_Biradar': {
        'password_hash': 'scrypt:32768:8:1$iFFHCHOzy9PoXLtI$c3ef8305e1d853ff...'  # Replace with actual hashed password from database
    }
}

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    message_username = None
    message_email = None
    message_password = None
    message_confirm_password = None

    if request.method == 'POST':
        username = request.form.get('username')

        # Validate username
        if not validate_input(username):
            message_username = 'Invalid username. Please use only alphanumeric characters, underscores, and hyphens.'
        else:
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            # Validate email
            if not email_pattern.match(email):
                message_email = 'Invalid email address.'

            # Validate password strength
            if not password_pattern.match(password):
                message_password = 'Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.'

            # Confirm password match
            if password != confirm_password:
                message_confirm_password = 'Passwords do not match.'

            # Check if user already exists
            if User.query.filter_by(username=username).first():
                message_username = 'Username already taken. Please choose another.'

        # If there are any error messages for username, return the form with the error message
        if message_username:
            return render_template('register.html', message_username=message_username)

        # If there are any error messages for email, password, or confirm password, return the form with the error messages
        if message_email or message_password or message_confirm_password:
            return render_template('register.html', message_username=message_username,
                                   message_email=message_email, message_password=message_password,
                                   message_confirm_password=message_confirm_password)

        # Hash the password
        password_hash = generate_password_hash(password)

        # Generate a TOTP secret
        otp_secret = pyotp.random_base32()

        # Create a new user instance
        new_user = User(username=username, email=email, password_hash=password_hash,
                        email_verified=False, otp_secret=otp_secret)

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Redirect the user to the login page after successful registration
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    message_username = None
    message_password = None

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        print("Received login request for username:", username)  # Debugging statement

        user = User.query.filter_by(username=username).first()

        if not user:
            message_username = 'Invalid username'
        elif not check_password_hash(user.password_hash, password):
            message_password = 'Invalid password'

        if message_username or message_password:
            return render_template('login.html', message_username=message_username, message_password=message_password)

        # If username and password are correct, prompt for OTP verification
        return render_template('otp.html', username=username, generate_qrcode=generate_qrcode)

    return render_template('login.html', message_username=None, message_password=None)

@app.route('/otp/<username>')
def otp(username):
    user = User.query.filter_by(username=username).first()
    if user:
        # Generate QR code for TOTP setup
        totp = pyotp.TOTP(user.otp_secret)
        issuer_name_bytes = 'YourApp'.encode('utf-8')  # Encoding the issuer_name to bytes
        totp_uri = totp.provisioning_uri(name=username, issuer_name=issuer_name_bytes)

        # Pass the generate_qrcode function to the template
        return render_template('otp.html', username=username, totp_uri=totp_uri, generate_qrcode=generate_qrcode)
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

@app.route('/verify-otp/<username>', methods=['POST'])
def verify_otp(username):
    user = User.query.filter_by(username=username).first()
    if user:
        totp = pyotp.TOTP(user.otp_secret)
        otp_code = request.form.get('otp_code')

        if totp.verify(otp_code):
            # Generate and send a new email verification code
            email_verification_code = generate_email_verification_code()
            send_email_verification(user.email, email_verification_code)
            
            # Store the new email verification code in the session for verification
            session['email_verification_code'] = email_verification_code

            flash('OTP verification successful. New email verification code sent.', 'success')
            return redirect(url_for('verify_email', username=username))
        else:
            flash('Invalid OTP code. Please try again.', 'danger')
            return redirect(url_for('login'))
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

@app.route('/verify-email/<username>', methods=['GET', 'POST'])
def verify_email(username):
    print("Received request to verify email for username:", username)  # Debugging statement
    
    if request.method == 'POST':
        email_verification_code = request.form.get('email_verification_code')
        session_code = session.get('email_verification_code')

        print("Received email verification code:", email_verification_code)  # Debugging statement
        print("Session email verification code:", session_code)  # Debugging statement

        if email_verification_code == session_code:
            flash('Email verification successful!', 'success')
            print("Redirecting to welcome page for username:", username)  # Debugging statement
            return redirect(url_for('welcome', username=username))  # Redirect to welcome page
        else:
            flash('Invalid email verification code. Please try again.', 'danger')
            return render_template('email_verification.html', username=username)
    #  # Get the user's email from the database using the username
    # user = User.query.filter_by(username=username).first()
    # if user:
    #     user_email = user.email
    #     flash(f"Please check your email '{user_email}' for the verification code.", 'info')
    #     return render_template('email_verification.html', username=username)
    # else:
    #     flash('User not found.', 'danger')
    #     return redirect(url_for('login'))

    return render_template('email_verification.html', username=username)

@app.route('/welcome/<username>')
def welcome(username):
    return render_template('welcome.html', username=username)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001)
