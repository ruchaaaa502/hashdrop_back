from datetime import datetime
from io import BytesIO
import io
import json
import re
import bcrypt
from flask import Blueprint, app, jsonify, render_template, request, redirect, send_file, session, url_for, flash, current_app
from flask_jwt_extended import current_user, get_jwt_identity, jwt_required
from pymongo import MongoClient
from app import mongo
from flask_mail import Mail, Message
import qrcode
from app.utils.constants import *
from app.utils.helpers import approve_request, reject_request
from bson import ObjectId
from datetime import datetime
import config
from bson import ObjectId
from flask import current_app


bp = Blueprint('admin', __name__)

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

@bp.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    """
    Displays the admin dashboard showing requests specific to the admin's organization.
    """
    if 'user_email' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('auth.login'))

    # Get current admin's details
    admin = mongo.db.users.find_one({
        "email": session['user_email'],
        "role": "admin"
    })

    if not admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('main.home'))

    # Get admin's organization
    organization = mongo.db.organizations.find_one({
        "admin_email": session['user_email']
    })

    if not organization:
        flash('Organization not found.', 'danger')
        return redirect(url_for('main.home'))

    # Get pending requests for this organization
    pending_requests = list(mongo.db.requests.find({
        'organization_id': organization['organization_id'],
        'status': 'pending'
    }).sort('request_date', -1))  # Sort by date, newest first

    # Get all members of this organization
    org_members = list(mongo.db.users.find({
        'organization_id': organization['organization_id']
    }, {'email': 1, 'name': 1, 'role': 1}))

    # Get all files shared within this organization
    org_files = list(mongo.db.files.find({
        'organization_id': organization['organization_id']
    }).sort('uploaded_at', -1))

    # Get organization stats
    stats = {
        'total_members': len(org_members),
        'total_files': len(org_files),
        'pending_requests': len(pending_requests),
        'organization_name': organization['organization_name']
    }

    return render_template('admin_dashboard.html',
                         requests=pending_requests,
                         members=org_members,
                         files=org_files,
                         stats=stats,
                         organization=organization)

@bp.route('/approve_request/<request_id>', methods=['POST'])
def admin_approve_request(request_id):
    approve_request(request_id)
    return redirect(url_for('admin.admin_dashboard'))

@bp.route('/deny_request/<request_id>', methods=['POST'])
def admin_deny_request(request_id):
    reject_request(request_id)
    return redirect(url_for('admin.admin_dashboard'))

@bp.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if 'user_email' not in session:
        flash('Login required.', 'danger')
        return redirect(url_for('login'))

    admin = mongo.db.users.find_one({"email": session['user_email'], "role": "admin"})
    if not admin:
        flash('Access denied. Only admins can add members.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        member_name = request.form['name']
        member_email = request.form['email']
        member_password = request.form['password']

        # Validate email format
        if not re.match(EMAIL_REGEX, member_email):
            flash('Invalid email address. Please enter a valid email.', 'danger')
            return render_template('add_member.html')

        # Check if the password meets security requirements
        if not re.match(PASSWORD_REGEX, member_password):
            flash('Password must meet the security requirements.', 'danger')
            return render_template('add_member.html')

        # Check if email already exists
        if mongo.db.users.find_one({"email": member_email}):
            flash('Email already registered.', 'danger')
            return render_template('add_member.html')

        # Hash the password and save the member details
        hashed_password = bcrypt.hashpw(member_password.encode('utf-8'), bcrypt.gensalt())
        mongo.db.users.insert_one({
            "name": member_name,
            "email": member_email,
            "password": hashed_password,
            "role": "user",
            "organization_id": admin['organization_id']
        })

        # Add member to the organization's member list
        mongo.db.organizations.update_one(
            {"organization_id": admin['organization_id']},
            {"$push": {"members": member_email}}
        )

        flash('Member added successfully!', 'success')
        return redirect(url_for('admin.admin_dashboard'))

    return render_template('add_member.html')

#required to fetch activities into tables
from flask import jsonify

@bp.route('/api/activities', methods=['GET'])
def get_activities_data():
    try:
        if 'user_email' not in session:
            return jsonify({'error': 'Unauthorized access'}), 401

        admin = mongo.db.users.find_one({
            "email": session['user_email'],
            "role": "admin"
        })

        if not admin:
            return jsonify({'error': 'Access denied'}), 403

        # Debug: Print the exact fields in activity logs
        activities = list(mongo.db.activity_logs.find({
            'organization_id': admin['organization_id']
        }).sort('timestamp', -1).limit(100))
        
        print("DEBUG - Activities:", [dict(act) for act in activities])

        activity_list = []
        for activity in activities:
            activity['_id'] = str(activity['_id'])

            # More verbose debugging
            print(f"Activity fields: {activity.keys()}")
            print(f"Filename field: {activity.get('filename', 'NO FILENAME FOUND')}")

            # Attempt multiple ways to get filename
            filename = (
                activity.get('filename') or 
                activity.get('file_name') or 
                activity.get('file', {}).get('filename') or 
                'N/A'
            )

            activity['filename'] = filename

            user = mongo.db.users.find_one({'email': activity['user_email']})
            if user:
                activity['user_name'] = user.get('name', 'Unknown')
            else:
                activity['user_name'] = 'Unknown'

            activity['timestamp'] = activity['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            activity_list.append(activity)

        return jsonify(activity_list), 200

    except Exception as e:
        print(f"ERROR in get_activities_data: {str(e)}")
        return jsonify({'error': f'Error fetching activities: {str(e)}'}), 500
    

@bp.route('/stats', methods=['GET'])
def get_stats():
    try:
        # Total counts
        total_files = mongo.db.files.count_documents({})
        total_activities = mongo.db.activity_log.count_documents({})
        error_count = mongo.db.activity_log.count_documents({'status': 'error'})

        # Get file type distribution from the files collection (using filename to determine type)
        file_types = mongo.db.files.aggregate([
            {
                '$group': {
                    '_id': {
                        '$toLower': {'$arrayElemAt': [{'$split': ['$file_name', '.']}, -1]}  # Use `file_name` from your schema
                    },
                    'count': {'$sum': 1}
                }
            }
        ])
        file_type_distribution = {file_type['_id']: file_type['count'] for file_type in file_types}

        # Get organization stats: total members
        organizations = mongo.db.organizations.find({})
        organization_stats = []
        for org in organizations:
            org_id = org.get('organization_id', 'Unknown')
            org_name = org.get('organization_name', 'Unnamed Organization')
            members = org.get('members', [])  # Assumes `members` is an array of member emails
            total_members = len(members)

            organization_stats.append({
                'organization_id': org_id,
                'organization_name': org_name,
                'total_members': total_members
            })

        # Return the stats as a JSON response
        return jsonify({
            'total_files': total_files,
            'total_activities': total_activities,
            'error_count': error_count,
            'file_type_distribution': file_type_distribution,
            'organization_stats': organization_stats
        }), 200

    except Exception as e:
        return jsonify({'error': f'Error fetching stats: {str(e)}'}), 500


#left
@bp.route('/activity_log', methods=['GET'])
def activity_log():
    """
    Displays activity logs for all users in the admin's organization.
    """

    # Fetch session variables for authentication and organization details
    admin_email = session.get('user_email')
    organization_id = session.get('organization_id')
    role = session.get('role')

    # Debugging session details
    print(f"Session Details - Admin Email: {admin_email}, Organization ID: {organization_id}, Role: {role}")

    # Verify if the user is logged in and is an admin
    if not admin_email or role != 'admin':
        flash('Access denied. Please log in as an admin to view activity logs.', 'danger')
        return redirect(url_for('auth.login'))

    # Ensure the admin exists and is linked to the organization
    admin = mongo.db.users.find_one({
        "email": admin_email,
        "role": "admin",
        "organization_id": organization_id
    })

    if not admin:
        flash('Admin not found. Please log in again.', 'danger')
        session.clear()  # Clear session to prevent stale data usage
        return redirect(url_for('auth.login'))

    # Fetch activity logs for users in the admin's organization only
    activity_logs = mongo.db.activity_logs.find({"organization_id": organization_id}).sort("timestamp", -1)
    activity_logs = list(activity_logs)  # Convert MongoDB cursor to a list for rendering
    print(f"Fetched Activity Logs: {activity_logs}")

    # Flash a message if no activity logs are found
    if not activity_logs:
        flash('No activity logs found for your organization.', 'info')

    # Pass the logs to the template for rendering
    return render_template('activity_log.html', logs=activity_logs)



@bp.route('/activities', methods=['GET'])
def admin_activities():
    """
    Renders the admin activities page.
    """
    return render_template('activity_log.html')


@bp.route('/organization_members')
def organization_members():
    admin = mongo.db.users.find_one({"email": session.get('user_email')})
    if admin and admin['role'] == 'admin':
        # Fetch members belonging to the admin's organization
        users = list(mongo.db.users.find({"organization_id": admin['organization_id']}))  # Ensure it's a list
        return render_template('manage_users.html', users=users)  # Pass 'users' to the template

    flash('Access denied.', 'danger')
    return redirect(url_for('home'))


@bp.route('/my_stored_files', methods=['GET'])
def my_stored_files():
    try:
        files = list(mongo.db.files.find({'uploaded_by': session.get('user_email')}))
        return render_template('admin_stored_files.html', files=files)
    except Exception as e:
        flash(f'Error retrieving files: {str(e)}', 'danger')
        return redirect(url_for('admin.upload_file'))

@bp.route('/download_file/<file_id>', methods=['POST'])
def download_file(file_id):
    try:
        file = mongo.db.files.find_one({'_id': ObjectId(file_id)})
        if not file:
            flash('File not found!', 'danger')
            return redirect(url_for('admin.my_stored_files'))

        file_data = BytesIO(file['file_data'])
        return send_file(
            file_data,
            as_attachment=True,
            download_name=file['filename']
        )
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'danger')
        return redirect(url_for('admin.my_stored_files'))

@bp.route('/delete_file/<file_id>', methods=['POST'])
def delete_file(file_id):
    try:
        result = mongo.db.files.delete_one({'_id': ObjectId(file_id)})
        if result.deleted_count > 0:
            flash('File deleted successfully!', 'success')
        else:
            flash('File not found or already deleted.', 'danger')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'danger')

    return redirect(url_for('admin.my_stored_files'))

@bp.route('/upload_file', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename.strip() == '':
            flash('No file selected for upload.', 'danger')
            return redirect(url_for('admin.upload_file'))

        try:
            filename = file.filename
            file_data = file.read()

            file_record = {
                'filename': filename,
                'file_data': file_data,
                'uploaded_by': session.get('user_email', 'admin'),
                'uploaded_at': datetime.now(),
            }
            result = mongo.db.files.insert_one(file_record)

            if result.inserted_id:
                flash('File uploaded successfully!', 'success')
                mongo.db.activity_log.insert_one({
                    'action': 'file_upload',
                    'filename': filename,
                    'uploaded_by': session.get('user_email', 'admin'),
                    'status': 'success',
                    'timestamp': datetime.now()
                })
            else:
                raise Exception('Failed to save file to the database.')

        except Exception as e:
            flash(f'Error during upload: {str(e)}', 'danger')
            mongo.db.activity_log.insert_one({
                'action': 'file_upload',
                'filename': filename if 'filename' in locals() else 'unknown',
                'uploaded_by': session.get('user_email', 'admin'),
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now()
            })

        return redirect(url_for('admin.upload_file'))

    return render_template('upload_file.html')


@bp.route('/user_stored_files', methods=['GET'])
def user_stored_files():
    """
    View all files uploaded by users within the organization.
    """
    try:
        # Check if the user is logged in
        if 'user_email' not in session:
            flash('Please log in to view user files.', 'warning')
            return redirect(url_for('auth.login'))

        # Check if the user is an admin
        admin = mongo.db.users.find_one({
            "email": session['user_email'],
            "role": "admin"
        })
        if not admin:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('admin.admin_dashboard'))  # Avoid redirect loop

        # Fetch files uploaded by users in the admin's organization
        files = list(mongo.db.files.find({
            'organization_id': admin['organization_id']
        }).sort('uploaded_at', -1))

        # Convert BSON ObjectId to string for easier handling in templates
        for file in files:
            file['_id'] = str(file['_id'])

        return render_template('user_stored_files.html', files=files)

    except Exception as e:
        # Log the error (optional, use a logging library in production)
        current_app.logger.error(f"Error retrieving user files: {e}")
        flash('An error occurred while retrieving user files. Please try again later.', 'danger')
        return redirect(url_for('admin.admin_dashboard'))

@bp.route('/download_file1/<file_id>', methods=['POST'])
def download_file1(file_id):
    try:
        # Fetch the file from the database
        file = mongo.db.files.find_one({'_id': ObjectId(file_id)})
        if not file:
            flash('File not found!', 'danger')
            return redirect(url_for('admin.user_stored_files'))

        # Assuming 'encrypted_data' contains the file data
        file_data = file.get('encrypted_data')
        if not file_data:
            flash('File data is empty or missing.', 'danger')
            return redirect(url_for('admin.user_stored_files'))

        # Convert to BytesIO for Flask send_file
        file_data_io = BytesIO(file_data)  # If stored as binary, this will work.
        return send_file(
            file_data_io,
            as_attachment=True,
            download_name=file.get('filename', 'downloaded_file')
        )
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'danger')
        return redirect(url_for('admin.user_stored_files'))

@bp.route('/delete_file1/<file_id>', methods=['POST'])
def delete_file1(file_id):
    try:
        # Validate ObjectId
        if not ObjectId.is_valid(file_id):
            flash('Invalid file ID.', 'danger')
            return redirect(url_for('admin.user_stored_files'))

        # Attempt to delete the file
        result = mongo.db.files.delete_one({'_id': ObjectId(file_id)})
        if result.deleted_count > 0:
            flash('File deleted successfully!', 'success')
        else:
            flash('File not found or already deleted.', 'danger')

    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'danger')

    return redirect(url_for('admin.user_stored_files'))
