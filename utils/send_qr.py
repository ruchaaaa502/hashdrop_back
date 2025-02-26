from datetime import datetime, timedelta
from io import BytesIO
import json
from bson import ObjectId
from flask import flash
from app import mongo, mail
from flask_mail import Message, Mail
import qrcode


def send_qr(request_id):
    try:
        user_request = mongo.db.requests.find_one({'_id': ObjectId(request_id)})
        if not user_request:
            raise ValueError("Request not found!")

        file_meta = mongo.db.files.find_one({'filename': user_request['file_name']})
        if not file_meta:
            raise ValueError("File not found!")

        # Create QR code data as a JSON string for better parsing
        qr_data = json.dumps({
            'request_id': str(request_id),
            'decryption_key': file_meta['encryption_key']
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
            sender=['MAIL_USERNAME'],
            recipients=[user_request['requested_by']]
        )
        msg.body = f'''Your QR code for file access is attached.
        This QR code will expire in 30 minutes.
        File: {user_request['file_name']}
        Permission Type: {user_request['permission_type']}
        '''
        msg.attach('qr_code.png', 'image/png', buffer.read())
        mail.send(msg)
    except Exception as e:
        flash(f"Error generating or sending QR: {str(e)}", 'danger')
