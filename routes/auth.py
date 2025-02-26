import os
from flask import Blueprint, app, current_app, request, render_template, redirect, url_for, flash, session
from app import mongo, mail
from flask_mail import Message
from datetime import datetime
import bcrypt
import secrets
import time
import re
from app.utils.constants import EMAIL_REGEX, PASSWORD_REGEX
from app.config import Config
import requests

bp = Blueprint('auth', __name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        organization_name = request.form['organization_name']

        # Validate the organization name
        organization = mongo.db.organizations.find_one({"organization_name": organization_name})
        if not organization:
            flash('Invalid organization name.', 'danger')
            return render_template('login.html')

        # Fetch the user and ensure they belong to the organization
        user = mongo.db.users.find_one({"email": email, "organization_id": organization['organization_id']})
        if not user:
            flash('Invalid email or organization.', 'danger')
            return render_template('login.html')

        # Check for account lock due to too many failed login attempts
        last_failed_time = user.get('last_failed_time', 0)
        if time.time() - last_failed_time > 86400:  # Reset failed attempts after 24 hours
            mongo.db.users.update_one({"email": email}, {"$set": {"failed_attempts": 0}})
        if user.get('failed_attempts', 0) >= 5:
            flash('Your account is locked due to too many failed login attempts. Please try again after 24 hours.', 'danger')
            return render_template('login.html')

        # Verify password
        if bcrypt.checkpw(password.encode('utf-8'), user['password'] if isinstance(user['password'], bytes) else user['password'].encode('utf-8')):
            # Reset failed attempts on successful login
            mongo.db.users.update_one({"email": email}, {"$set": {"failed_attempts": 0, "last_failed_time": 0}})

            # Generate OTP for both admin and regular users
            otp = secrets.token_hex(3)  # 6-character OTP in hexadecimal
            session['otp'] = otp
            session['otp_time'] = time.time()
            session['user_email'] = email
            session['organization_id'] = user['organization_id']
            session['role'] = user['role']

            # Send OTP via email
            msg = Message("Your OTP for Login", recipients=[email])
            msg.html = f"""
            <html>
            <head>
                <title>Your Hashdrop OTP</title>
                <style>
                    h1 {{
                        color: #f76c6c;
                        font-size: 32px;
                    }}
                    .otp {{
                        font-size: 24px;
                        color: #4caf50;
                        font-weight: bold;
                    }}
                </style>
            </head>
            <body>
                <h1>Hi {user['name']}!</h1>
                <p>Your OTP for logging into Hashdrop is: <span class="otp">{otp}</span></p>
            </body>
            </html>
            """
            mail.send(msg)

            flash('OTP has been sent to your email. Please enter it below.', 'info')
            return redirect(url_for('auth.verify_otp'))

        else:
            # Increment failed attempts on incorrect password
            mongo.db.users.update_one(
                {"email": email},
                {"$inc": {"failed_attempts": 1}, "$set": {"last_failed_time": time.time()}}
            )
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')



@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get hCaptcha response from the form
        captcha_response = request.form['h-captcha-response']

        # Verify hCaptcha response using keys from config
        secret_key = current_app.config['HCAPTCHA_SECRET_KEY']
        captcha_verify_url = "https://hcaptcha.com/siteverify"
        captcha_data = {
            "secret": secret_key,
            "response": captcha_response
        }

        # Send POST request to hCaptcha verify API
        response = requests.post(captcha_verify_url, data=captcha_data)
        result = response.json()

        # Check hCaptcha success
        if not result.get("success", False):
            flash('hCaptcha verification failed. Please try again.', 'danger')
            return render_template('register.html', hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])

        # Get form data
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = 'admin'  # Restricting registration to admins only
        organization_name = request.form['organization_name']

        # Validate email
        if not re.match(EMAIL_REGEX, email):
            flash('Invalid email address.', 'danger')
            return render_template('register.html', hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])

        # Validate password
        if not re.match(PASSWORD_REGEX, password):
            flash('Password is too weak.', 'danger')
            return render_template('register.html', hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])

        # Check if email is already registered
        if mongo.db.users.find_one({"email": email}):
            flash('Email already registered.', 'danger')
            return render_template('register.html', hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])

        # Check if organization already exists
        existing_org = mongo.db.organizations.find_one({"organization_name": organization_name})
        if existing_org:
            flash('Organization name already exists. Please choose a different name.', 'danger')
            return render_template('register.html', hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])

        # Generate a unique organization ID
        organization_id = secrets.token_hex(6)

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert organization into the database
        mongo.db.organizations.insert_one({
            "organization_id": organization_id,
            "organization_name": organization_name,
            "admin_email": email,
            "members": []  # Initialize empty member list
        })

        # Insert admin user into the database
        mongo.db.users.insert_one({
            "name": name,
            "email": email,
            "password": hashed_password,
            "role": role,
            "organization_id": organization_id
        })

        flash('Registration successful! Organization created.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html', hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])


@bp.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('auth.login'))



@bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')  # Safely get email input

        # Find the user by email in the database
        user = mongo.db.users.find_one({"email": email})

        if user:
            if user.get('role') == 'admin':
                # Generate OTP and store it in the session
                otp = secrets.token_hex(3)  # Generate a 6-character hexadecimal OTP
                session['forgot_otp'] = otp
                session['forgot_otp_time'] = time.time()
                session['forgot_user_email'] = email

                # Prepare and send the email
                try:
                    msg = Message("HashDrop OTP", recipients=[email])
                    msg.body = f"Your OTP for resetting your password is: {otp}"
                    mail.send(msg)

                    flash('OTP has been sent to your email. Please enter it below to reset your password.', 'info')
                    return redirect(url_for('auth.verify_forgot_otp'))
                except Exception as e:
                    flash('Error sending OTP email. Please try again later.', 'danger')
                    return redirect(url_for('auth.forgot_password'))
            else:
                flash('Only admins can reset passwords. Please contact your admin.', 'info')
                return redirect(url_for('auth.login'))
        else:
            flash('Email not registered.', 'danger')
            return redirect(url_for('auth.forgot_password'))

    return render_template('forgot_password.html')



@bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        otp_input = request.form['otp']

        if session['otp'] == otp_input and time.time() - session['otp_time'] <= 300:
            flash('OTP verified successfully. Welcome!', 'success')
            if session.get('role') == 'admin':
                return redirect(url_for('admin.admin_dashboard'))
            return redirect(url_for('user.user_dashboard'))

        flash('Invalid or expired OTP. Please try again.', 'danger')

    return render_template('verify_otp.html')


@bp.route('/verify-forgot-otp', methods=['GET', 'POST'])
def verify_forgot_otp():
    if 'forgot_otp' not in session:
        flash('Session expired. Please request a password reset again.', 'warning')
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        otp_input = request.form['otp']

        if session['forgot_otp'] == otp_input and time.time() - session['forgot_otp_time'] <= 300:
            flash('OTP verified successfully. You can now reset your password.', 'success')
            return redirect(url_for('auth.reset_password'))

        flash('Invalid OTP or OTP expired. Please try again.', 'danger')

    return render_template('verify_forgot_otp.html')


@bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'forgot_user_email' not in session:
        flash('Session expired. Please request a password reset again.', 'warning')
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Please fill in all fields.', 'danger')
            return render_template('reset_password.html')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html')

        if not re.match(PASSWORD_REGEX, new_password):
            flash('Password does not meet requirements.', 'danger')
            return render_template('reset_password.html')

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        # Update password in the database
        email = session['forgot_user_email']
        mongo.db.users.update_one({"email": email}, {"$set": {"password": hashed_password}})

        # Clear session variables related to password reset
        session.pop('forgot_user_email', None)
        session.pop('forgot_otp', None)
        session.pop('forgot_otp_time', None)

        flash('Password reset successfully. You can now log in with your new password.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html')
