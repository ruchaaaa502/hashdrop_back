from base64 import urlsafe_b64encode
import base64
import hashlib
import json
import cv2
from flask import Blueprint, app, jsonify, render_template, request, redirect, url_for, flash, session
from flask_mail import Message
from app import mongo, mail
from bson import ObjectId
import pytz
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from zoneinfo import ZoneInfo  # If using zoneinfo for time zones
from cryptography.fernet import Fernet
from app.utils.helpers import process_file_access
from utils.encryption import *


# Define IST timezone
ist_timezone = pytz.timezone('Asia/Kolkata')

# Get the current IST time
uploaded_at = datetime.now(ist_timezone)

bp = Blueprint('user', __name__)

@bp.route('/user_info', methods=['GET'])
def get_user_info():
    """
    Retrieve current user's name and role
    """
    if 'user_email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user = mongo.db.users.find_one({
        'email': session['user_email']
    }, {
        'name': 1, 
        'role': 1
    })

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'name': user.get('name', 'Unknown'),
        'role': user.get('role', 'User')
    })

# User Dashboard Route
@bp.route('/dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if 'user_email' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('auth.login'))  # Redirect to the login route

    email = session['user_email']
    user_files = mongo.db.files.find({'uploaded_by': email})  # Fetch user-specific files from the database

    if request.method == 'POST' and 'file' in request.files:
        file = request.files['file']
        if file and file.filename:
            filename = secure_filename(file.filename)
            file_path = os.path.join('uploads', filename)
            file.save(file_path)

            # Save file metadata to the database
            mongo.db.files.insert_one({
                'filename': filename,
                'file_path': file_path,
                'uploaded_by': email,
                'uploaded_at': uploaded_at,
            })

            flash('File uploaded successfully!', 'success')
            return redirect(url_for('user.user_dashboard'))
        else:
            flash('No file selected for upload.', 'danger')

    return render_template('user_dashboard.html', files=user_files)


@bp.route('/request_permission/<file_id>', methods=['POST'])
def request_permission(file_id):
    """
    Handle permission requests for file access with organization context.
    """
    if 'user_email' not in session:
        flash('Please log in to request permissions.', 'warning')
        return redirect(url_for('auth.login'))

    try:
        user_email = session['user_email']
        
        # Get user details
        user = mongo.db.users.find_one({
            "email": user_email
        })
        
        if not user:
            flash('User details not found.', 'danger')
            return redirect(url_for('user.user_dashboard'))

        # Get organization details
        organization = mongo.db.organizations.find_one({
            "organization_id": user['organization_id'],
            "members": user_email  # Verify user is a member
        })

        if not organization:
            flash('Organization details not found or unauthorized access.', 'danger')
            return redirect(url_for('user.user_dashboard'))

        # Get file details
        file = mongo.db.files.find_one({'_id': ObjectId(file_id)})
        if not file:
            flash('File not found.', 'danger')
            return redirect(url_for('user.user_dashboard'))

        # Check if user already has a pending request for this file
        existing_request = mongo.db.requests.find_one({
            'file_id': ObjectId(file_id),
            'requested_by': user_email,
            'status': 'pending'
        })

        if existing_request:
            flash('You already have a pending request for this file.', 'warning')
            return redirect(url_for('user.user_dashboard'))

        # Get request details from form
        permission_type = request.form['permission_type']  # read/write
        purpose = request.form.get('purpose', '')  # Optional purpose field
        duration = request.form.get('duration', '24')  # Access duration in hours

        # Create the request
        request_data = {
            'file_id': ObjectId(file_id),
            'file_name': file['filename'],
            'requested_by': user_email,
            'requester_name': user['name'],
            'organization_id': organization['organization_id'],
            'admin_email': organization['admin_email'],
            'permission_type': permission_type,
            'purpose': purpose,
            'requested_duration': int(duration),
            'status': 'pending',
            'request_date': datetime.now(),
            'organization_name': organization['organization_name']
        }

        # Insert request
        mongo.db.requests.insert_one(request_data)

        # Send email notification to admin
       
         # Log the activity
        mongo.db.activity_logs.insert_one({
            'organization_id': organization['organization_id'],
            'action': 'permission_requested',
            'user_email': user_email,
            'file_id': file_id,
            'file_name': file['filename'],
            'permission_type': permission_type,
            'timestamp': datetime.now()
        })

        flash('Permission request submitted successfully! You will receive an email when it is processed.', 'success')

    except Exception as e:
        flash(f'Error submitting request: {str(e)}', 'danger')

    return redirect(url_for('user.user_dashboard'))

@bp.route('/access-file_page', methods=['GET'])
def access_file_page():
    return render_template('access_file.html')

@bp.route('/upload_file', methods=['POST'])
def upload_file():
    """
    Handles file uploads, encrypts the file, and saves it to the database with the encryption key.
    """
    try:
        # Check if the file is in the request
        if 'file' not in request.files:
            flash('No file part in the request.', 'danger')
            return redirect(url_for('user.user_dashboard'))

        file = request.files['file']

        # Check if the file has a valid name
        if not file or file.filename.strip() == '':
            flash('No file selected for upload.', 'danger')
            return redirect(url_for('user.user_dashboard'))

        # Generate a secure filename
        filename = secure_filename(file.filename)
        file_data = file.read()  # Read file content as binary data

        # Generate an encryption key
        raw_key = hashlib.sha256(f"{filename}{uploaded_at.timestamp()}".encode()).digest()
        encryption_key = urlsafe_b64encode(raw_key[:32])  # URL-safe base64-encoded, 32-byte key

        # Encrypt the file data
        fernet = Fernet(encryption_key)
        encrypted_data = fernet.encrypt(file_data)

        # Prepare the document for database insertion
        uploaded_file = {
            'filename': filename,
            'encryption_key': encryption_key.decode(),  # Store key as a string
            'encrypted_data': encrypted_data,
            'organization_id': session.get('organization_id'),
            'uploaded_at': uploaded_at,
            'uploaded_by': session.get('user_email')  # Ensure user_email is stored in the session
        }

        mongo.db.activity_logs.insert_one({
            'organization_id': session.get('organization_id'),
            'user_email': session.get('user_email'),
            'file_name': filename,
            'action': 'file_uploaded',
            'timestamp': datetime.now(),
        })
        # Insert the document into the database
        result = mongo.db.files.insert_one(uploaded_file)

        if result.inserted_id:
            flash('File uploaded and encrypted successfully!', 'success')
        else:
            flash('Failed to save the file in the database.', 'danger')

    except Exception as e:
        # Log the error for debugging purposes
        print(f"Error during file upload: {e}")
        flash(f"An error occurred while uploading the file: {str(e)}", 'danger')

    return redirect(url_for('user.user_dashboard'))

@bp.route('/stored_files', methods=['GET'])
def stored_files():
   
    user_email = session.get('user_email')

    if not user_email:
        return render_template('error.html', message="Please log in to view your stored files.")

    files = mongo.db.files.find({'uploaded_by': user_email})
    return render_template('stored_files.html', files=files)

@bp.route('/settings', methods=['GET'])
def permission():
    user_email = session.get('user_email')
    if not user_email:
        return render_template('error.html', message="Please log in to access settings.")

    return render_template('permission.html')

@bp.route('/access_file', methods=['POST'])
def access_file():
    qr_code_file = request.files.get('qr_code_file')

    if not qr_code_file:
        flash('QR code file is required.', 'danger')
        return redirect(url_for('user.access_file_page'))

    try:
        # Save the uploaded QR code image temporarily
        temp_file_path = "temp_qr_code.png"
        qr_code_file.save(temp_file_path)

        # Read and decode QR code
        img = cv2.imread(temp_file_path)
        if img is None:
            flash('Invalid image file.', 'danger')
            return redirect(url_for('user.access_file_page'))

        # Convert image to grayscale for better QR detection
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Initialize QR code detector
        qr_code_detector = cv2.QRCodeDetector()
        decoded_data, points, _ = qr_code_detector.detectAndDecode(gray)

        if not decoded_data:
            flash('Unable to decode the QR code.', 'danger')
            return redirect(url_for('user.access_file_page'))

        # Parse the JSON data from QR code
        try:
            data_dict = json.loads(decoded_data)
            request_id = data_dict['request_id']
            decryption_key = data_dict['decryption_key']
        except json.JSONDecodeError:
            flash('Invalid QR code format.', 'danger')
            return redirect(url_for('user.access_file_page'))

        # Clean up temporary file
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

        # Validate request and file
        user_request = mongo.db.requests.find_one({'_id': ObjectId(request_id)})
        if not user_request:
            flash('Invalid request ID.', 'danger')
            return redirect(url_for('user.access_file_page'))

        # Check QR expiry
        if user_request.get('qr_expiry') and datetime.now() > user_request['qr_expiry']:
            flash('The QR code has expired.', 'danger')
            return redirect(url_for('user.access_file_page'))

        # Get file metadata
        file_meta = mongo.db.files.find_one({'filename': user_request['file_name']})
        if not file_meta:
            flash('File not found.', 'danger')
            return redirect(url_for('user.access_file_page'))

        # Verify decryption key
        if decryption_key != file_meta.get('encryption_key'):
            flash('Invalid decryption key.', 'danger')
            return redirect(url_for('user.access_file_page'))

        mongo.db.activity_logs.insert_one({
            'organization_id': session.get('organization_id'),
            'user_email': session.get('user_email'),
            'file_name': file_meta['filename'],
            'action': 'file_accessed',
            'timestamp': datetime.now(),
        })
        # Process the file based on permission type
        return process_file_access(user_request, file_meta, decryption_key)

    except Exception as e:
        flash(f'Error processing request: {str(e)}', 'danger')
        return redirect(url_for('user.access_file_page'))
    

    