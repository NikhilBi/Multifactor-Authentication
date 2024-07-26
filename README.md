# Flask Web Application

## Description

This Flask web application provides secure user registration and login functionalities using SQLAlchemy for database management. It includes features such as strong password validation, two-factor authentication (2FA) with TOTP, and QR code generation for added security. Email verification is implemented using SMTP to ensure user authenticity, protecting against unauthorized access while maintaining ease of use and robust security.

## Features

- **User Registration**: Secure user registration with strong password validation.
- **User Login**: Secure login with password hashing.
- **Two-Factor Authentication (2FA)**: TOTP-based 2FA with QR code generation.
- **Email Verification**: SMTP-based email verification.
- **Input Validation**: Validates input to prevent security vulnerabilities.
- **Session Management**: Manages user sessions securely.

## Requirements

- Python 3.x
- Flask
- Flask-SQLAlchemy
- PyOTP
- qrcode
- Pillow
- re
- smtplib
- email
- secrets
- MySQL

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/yourusername/your-repo.git
    ```

2. Navigate to the project directory:

    ```sh
    cd your-repo
    ```

3. Install the required packages:

    ```sh
    pip install -r requirements.txt
    ```

4. Configure the database URI in `app.config`:

    ```python
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost:3306/app'
    ```

5. Set up the database:

    ```sh
    flask db init
    flask db migrate
    flask db upgrade
    ```

## Usage

1. Run the Flask application:

    ```sh
    python app.py
    ```

2. Open your web browser and go to `http://127.0.0.1:5001`.

## Routes

- `/`: Home page.
- `/register`: User registration page.
- `/login`: User login page.
- `/otp/<username>`: OTP verification page.
- `/verify-otp/<username>`: Verifies the OTP code.
- `/verify-email/<username>`: Email verification page.
- `/welcome/<username>`: Welcome page after successful login.

## Contributing

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Credits

Designed by Nikhil.
