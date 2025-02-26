import base64
from datetime import datetime, timedelta
from io import BytesIO
import json
from bson import ObjectId
from flask import app, current_app, flash, redirect, render_template, url_for
from flask_mail import Mail, Message
from pymongo import MongoClient
from app import mongo, mail
import qrcode
from app.utils.encryption import *

from config import Config
def log_activity(action, user_email, details):
    """
    Logs an activity in the database.
    """
    try:
        log_entry = {
            'timestamp': datetime.now(),
            'action': action,
            'user_email': user_email,
            'details': details
        }
        mongo.db.activity_logs.insert_one(log_entry)
    except Exception as e:
        # Handle any exceptions related to logging
        print(f"Failed to log activity: {e}")

def send_qr(request_id):
    try:
        # Fetch the request details from the database
        user_request = mongo.db.requests.find_one({'_id': ObjectId(request_id)})
        if not user_request:
            raise ValueError("Request not found!")

        # Fetch the file meta information based on the file name
        file_meta = mongo.db.files.find_one({'filename': user_request['file_name']})
        if not file_meta:
            raise ValueError(f"File with filename '{user_request['file_name']}' not found.")

        # Create QR code data as a JSON string for better parsing
        qr_data = json.dumps({
            'request_id': str(request_id),
            'decryption_key': file_meta['encryption_key']  # Assuming the 'encryption_key' exists
        })
        
        # Generate QR code
        qr = qrcode.make(qr_data)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        buffer.seek(0)

        # Set QR code expiration (30 minutes)
        qr_expiry = datetime.now() + timedelta(minutes=30)
        mongo.db.requests.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': {'qr_expiry': qr_expiry}}
        )

        # Send email with QR code
        msg = Message(
    'Your File Access QR Code',
    sender=current_app.config['MAIL_USERNAME'],
    recipients=[user_request['requested_by']]  # This should be the user who made the request
)
        msg.body = f'''Your QR code for file access is attached.
        This QR code will expire in 30 minutes.
        File: {user_request['file_name']}
        Permission Type: {user_request['permission_type']}
        '''
        msg.attach('qr_code.png', 'image/png', buffer.read())
        mail.send(msg)

        log_activity('qr_sent', user_request['requested_by'], {
            'file_name': user_request['file_name'],
            'permission_type': user_request['permission_type']
        })

    except ValueError as ve:
        flash(f"Error: {str(ve)}", 'danger')
    except Exception as e:
        flash(f"An error occurred while generating or sending the QR code: {str(e)}", 'danger')

def approve_request(request_id):
    """
    Approves a user's request and sends a QR code via email.
    """
    try:
        user_request = mongo.db.requests.find_one({'_id': ObjectId(request_id)})

        if not user_request:
            flash('Request not found!', 'danger')
            return

        # Update the request status to 'approved'
        mongo.db.requests.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': {'status': 'approved', 'approved_at': datetime.now()}}
        )

        # Generate and send the QR code via email
        send_qr(request_id)

        log_activity('approved', user_request['requested_by'], {
            'file_name': user_request['file_name'],
            'permission_type': user_request['permission_type']
        })

        flash('Request approved successfully!', 'success')
    except Exception as e:
        flash(f'An error occurred while approving the request: {str(e)}', 'danger')


def reject_request(request_id):
    """
    Rejects a user's request and notifies them via email.
    """
    try:
        user_request = mongo.db.requests.find_one({'_id': ObjectId(request_id)})

        if not user_request:
            flash('Request not found!', 'danger')
            return

        # Update the request status to 'rejected'
        mongo.db.requests.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': {'status': 'rejected', 'rejected_at': datetime.now()}}
        )

        # Notify the user via email
        user_email = user_request['requested_by']
        msg = Message(
            'Permission Request Denied',
            sender=current_app.config['MAIL_USERNAME'],
            recipients=[user_email]
        )
        msg.body = f"""Hello,

We regret to inform you that your permission request for the file "{user_request['file_name']}" has been denied.

If you have any questions, please contact the administrator.

Thank you,
Hashdrop Team
"""
        mail.send(msg)

        log_activity('rejected', user_email, {
            'file_name': user_request['file_name'],
            'permission_type': user_request['permission_type']
        })

        flash('Request denied successfully! Email notification sent to the user.', 'success')
    except Exception as e:
        flash(f'An error occurred while rejecting the request: {str(e)}', 'danger')



def process_file_access(user_request, file_meta, decryption_key):
    """
    Helper function to process file access based on permission type with activity logging.
    """
    # Check if QR code has already been used
    if user_request.get('qr_used', False):
        flash('This QR code has already been used and cannot be reused.', 'danger')
        log_activity('qr_reuse_attempt', user_request['requested_by'], {
            'file_name': file_meta['filename']
        })
        return redirect(url_for('access_file_page'))

    permission_type = user_request['permission_type']

    try:
        # Decrypt the file data
        decrypted_data = decrypt_file(file_meta['encrypted_data'], decryption_key)
        filename = file_meta['filename']
        file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        mime_type = get_mime_type(file_ext)

        # Mark QR code as used
        mongo.db.requests.update_one(
            {'_id': user_request['_id']},
            {'$set': {'qr_used': True}}
        )
        log_activity('qr_used', user_request['requested_by'], {
            'file_name': file_meta['filename'],
            'permission_type': permission_type
        })

        if permission_type == 'view':
            # Convert data to base64 for secure viewing
            file_b64 = base64.b64encode(decrypted_data).decode()

            # Special handling for PDFs
            if mime_type == 'application/pdf':
                pdf_data = f"data:application/pdf;base64,{file_b64}"
                log_activity('file_viewed', user_request['requested_by'], {
                    'file_name': filename,
                    'file_type': mime_type
                })
                return render_template('secure_view.html',
                                       file_data=pdf_data,
                                       filename=filename,
                                       mime_type=mime_type,
                                       is_text=False)

            # For text-based files
            elif mime_type.startswith('text/') or mime_type in ['application/json', 'application/javascript']:
                try:
                    decoded_content = decrypted_data.decode('utf-8')
                    log_activity('file_viewed', user_request['requested_by'], {
                        'file_name': filename,
                        'file_type': mime_type
                    })
                    return render_template('secure_view.html',
                                           file_content=decoded_content,
                                           filename=filename,
                                           mime_type=mime_type,
                                           is_text=True)
                except UnicodeDecodeError:
                    pass  # Fallback to binary display if decoding fails

            # For other file types
            log_activity('file_viewed', user_request['requested_by'], {
                'file_name': filename,
                'file_type': mime_type
            })
            return render_template('secure_view.html',
                                   file_data=f"data:{mime_type};base64,{file_b64}",
                                   filename=filename,
                                   mime_type=mime_type,
                                   is_text=False)

        elif permission_type == 'delete':
            # Delete the file from the database
            mongo.db.files.delete_one({'_id': file_meta['_id']})
            mongo.db.requests.update_one(
                {'_id': user_request['_id']},
                {'$set': {'status': 'completed'}}
            )
            log_activity('file_deleted', user_request['requested_by'], {
                'file_name': filename
            })
            flash('File deleted successfully!', 'success')
            return render_template('file_deleted.html')

        else:
            flash('Invalid permission type.', 'danger')
            log_activity('invalid_permission_type', user_request['requested_by'], {
                'file_name': filename,
                'permission_type': permission_type
            })
            return redirect(url_for('access_file_page'))

    except Exception as e:
        flash(f'Error processing file: {str(e)}', 'danger')
        log_activity('file_access_error', user_request['requested_by'], {
            'file_name': filename,
            'error': str(e)
        })
        return redirect(url_for('access_file_page'))

# Updated get_mime_type function with more comprehensive MIME types
def get_mime_type(file_ext):
    """Determine MIME type based on file extension."""
    mime_types = {
        # Text files
        'txt': 'text/plain',
        'csv': 'text/csv',
        'md': 'text/markdown',
        'py': 'text/plain',  # Changed to plain text for better viewing
        'js': 'text/plain',  # Changed to plain text for better viewing
        'html': 'text/html',
        'css': 'text/plain',
        'json': 'text/plain',  # Changed to plain text for better viewing
        'xml': 'text/plain',
        
        # Images
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif',
        'svg': 'image/svg+xml',
        'webp': 'image/webp',
        
        # Documents
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'ppt': 'application/vnd.ms-powerpoint',
        'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        
        # Archives
        'zip': 'application/zip',
        'rar': 'application/x-rar-compressed',
        '7z': 'application/x-7z-compressed',
        
        # Audio
        'mp3': 'audio/mpeg',
        'wav': 'audio/wav',
        'ogg': 'audio/ogg',
        
        # Video
        'mp4': 'video/mp4',
        'avi': 'video/x-msvideo',
        'mkv': 'video/x-matroska'
    }
    return mime_types.get(file_ext, 'application/octet-stream')