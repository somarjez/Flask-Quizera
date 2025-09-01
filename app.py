from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config, db
from google.cloud.firestore import Increment  # Add this import
import uuid
from datetime import datetime
from firebase_admin import firestore
from google.cloud.firestore_v1 import Increment
import json
from flask import request, jsonify
from flask_mail import Mail, Message
import secrets
from datetime import datetime, timezone, timedelta 
import hashlib
from google.cloud.firestore_v1 import FieldFilter


app = Flask(__name__)
app.config.from_object(Config)
mail = Mail(app)

class User:
    def __init__(self, user_id, username, email, role):
        self.id = user_id
        self.username = username
        self.email = email
        self.role = role

@app.template_filter('get_animal_emoji')
def get_animal_emoji(animal_id):
    """Template filter to get animal emoji"""
    animal_emojis = {
        'cat': '🐱', 'dog': '🐶', 'fox': '🦊', 'bear': '🐻', 'panda': '🐼', 'koala': '🐨',
        'lion': '🦁', 'tiger': '🐯', 'wolf': '🐺', 'rabbit': '🐰', 'monkey': '🐵', 'elephant': '🐘',
        'penguin': '🐧', 'owl': '🦉', 'turtle': '🐢', 'unicorn': '🦄'
    }
    return animal_emojis.get(animal_id, '🐱')

@app.route('/update-avatar', methods=['POST'])
def update_avatar():
    print(f"DEBUG: Update avatar called")  # Debug line
    
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in'}), 401
    
    try:
        data = request.get_json()
        avatar_type = data.get('avatar_type')
        avatar_id = data.get('avatar_id')
        
        print(f"DEBUG: Avatar type: {avatar_type}, Avatar ID: {avatar_id}")  # Debug line
        
        if not avatar_type or not avatar_id:
            return jsonify({'success': False, 'message': 'Invalid avatar data'}), 400
        
        # Update user document
        user_ref = db.collection('users').document(session['user_id'])
        update_data = {
            'avatar_type': avatar_type,
            'avatar_id': avatar_id,
            'updated_at': datetime.now()
        }
        
        user_ref.update(update_data)
        print(f"DEBUG: User avatar updated successfully")  # Debug line
        
        return jsonify({'success': True, 'message': 'Avatar updated successfully'})
        
    except Exception as e:
        print(f"ERROR updating avatar: {e}")
        return jsonify({'success': False, 'message': 'Error updating avatar'}), 500
@app.route('/')
def home():
    # Get all subjects from teachers
    subjects = []
    try:
        subjects_ref = db.collection('subjects')
        docs = subjects_ref.stream()
        
        for doc in docs:
            subject_data = doc.to_dict()
            subject_data['id'] = doc.id
            
            # Check enrollment status if user is logged in
            if 'user_id' in session and session.get('role') == 'student':
                subject_data['is_enrolled'] = check_enrollment(session['user_id'], doc.id)
            else:
                subject_data['is_enrolled'] = False
            
            subjects.append(subject_data)
    except Exception as e:
        print(f"Error fetching subjects: {e}")
    
    # Pass session information to template
    username = session.get('username')
    role = session.get('role')
    
    return render_template('home.html', 
                         subjects=subjects, 
                         username=username, 
                         role=role)

# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     if request.method == 'POST':
#         username = request.form['username']
#         email = request.form['email']
#         password = request.form['password']
#         role = request.form['role']
        
#         # Check if user already exists
#         users_ref = db.collection('users')
#         existing_user = users_ref.where('email', '==', email).get()
        
#         if existing_user:
#             flash('Email already exists. Please use a different email.')
#             return render_template('signup.html')
        
#         # Hash password
#         hashed_password = generate_password_hash(password)
        
#         # Create user document
#         user_data = {
#             'username': username,
#             'email': email,
#             'password': hashed_password,
#             'role': role,
#             'created_at': datetime.now()
#         }
        
#         try:
#             doc_ref = users_ref.add(user_data)
#             flash('Account created successfully! Please log in.')
#             return redirect(url_for('login'))
#         except Exception as e:
#             flash(f'Error creating account: {e}')
#             return render_template('signup.html')
    
#     return render_template('signup.html')
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']
        
        # Validation
        if not username or not email or not password or not confirm_password:
            flash('Please fill in all fields.')
            return render_template('signup.html')
        
        if len(username) < 3:
            flash('Username must be at least 3 characters long.')
            return render_template('signup.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.')
            return render_template('signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match.')
            return render_template('signup.html')
        
        # Check if user already exists
        users_ref = db.collection('users')
        existing_user = users_ref.where('email', '==', email).get()
        
        if existing_user:
            flash('Email already exists. Please use a different email.')
            return render_template('signup.html')
        
        # Check if username already exists
        existing_username = users_ref.where('username', '==', username).get()
        if existing_username:
            flash('Username already exists. Please choose a different username.')
            return render_template('signup.html')
        
        try:
            # Hash password
            hashed_password = generate_password_hash(password)
            
            # Generate email confirmation token
            confirmation_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(confirmation_token.encode()).hexdigest()
            
            # Set token expiration (24 hours from now)
            current_time = datetime.now(timezone.utc)
            expires_at = current_time + timedelta(hours=24)
            
            # Create pending user document (not activated yet)
            user_data = {
                'username': username,
                'email': email,
                'password': hashed_password,
                'role': role,
                'is_verified': False,
                'verification_token_hash': token_hash,
                'token_expires_at': expires_at,
                'created_at': current_time
            }
            
            # Save user to 'pending_users' collection instead of 'users'
            pending_users_ref = db.collection('pending_users')
            doc_ref = pending_users_ref.add(user_data)
            
            # Send confirmation email
            confirmation_url = url_for('confirm_email', token=confirmation_token, _external=True)
            
            msg = Message(
                'Welcome to Quizera - Confirm Your Email',
                recipients=[email],
                html=f'''
                <html>
                <body>
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <div style="background-color: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
                            <h1 style="margin: 0; font-size: 28px;">Welcome to Quizera!</h1>
                        </div>
                        <div style="padding: 30px; border: 1px solid #e5e5e5; border-radius: 0 0 10px 10px;">
                            <h2 style="color: #2563eb;">Confirm Your Email Address</h2>
                            <p>Hello {username},</p>
                            <p>Thank you for signing up for Quizera! To complete your registration and activate your account, please click the button below to confirm your email address:</p>
                            
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{confirmation_url}" 
                                   style="background-color: #2563eb; color: white; padding: 15px 30px; 
                                          text-decoration: none; border-radius: 8px; display: inline-block;
                                          font-weight: bold; font-size: 16px;">
                                    Confirm Email Address
                                </a>
                            </div>
                            
                            <p>Or copy and paste this link into your browser:</p>
                            <p style="word-break: break-all; background-color: #f8f9fa; padding: 10px; border-radius: 5px; font-family: monospace;">
                                <a href="{confirmation_url}">{confirmation_url}</a>
                            </p>
                            
                            <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
                                <p style="margin: 0; color: #856404;"><strong>Important:</strong> This confirmation link will expire in 24 hours. If you don't confirm your email within this time, you'll need to sign up again.</p>
                            </div>
                            
                            <p>Once you confirm your email, you'll be able to:</p>
                            <ul style="color: #555;">
                                <li>Access your personalized dashboard</li>
                                <li>{"Create and manage quizzes and subjects" if role == "teacher" else "Enroll in subjects and take quizzes"}</li>
                                <li>Track your progress and achievements</li>
                            </ul>
                            
                            <p>If you didn't create an account with Quizera, please ignore this email.</p>
                            
                            <hr style="margin: 30px 0; border: 1px solid #e5e5e5;">
                            <p style="color: #666; font-size: 12px; text-align: center;">
                                This is an automated message from Quizera. Please do not reply to this email.<br>
                                Need help? Contact our support team.
                            </p>
                        </div>
                    </div>
                </body>
                </html>
                '''
            )
            
            mail.send(msg)
            flash('Account created successfully! Please check your email and click the confirmation link to activate your account.')
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Error creating account: {e}")
            flash(f'Error creating account: {e}')
            return render_template('signup.html')
    
    return render_template('signup.html')

# Add this new route for email confirmation
@app.route('/confirm-email/<token>')
def confirm_email(token):
    try:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Find pending user with this token
        pending_users_ref = db.collection('pending_users')
        pending_docs = list(pending_users_ref.where('verification_token_hash', '==', token_hash).where('is_verified', '==', False).get())
        
        if not pending_docs:
            flash('Invalid or expired confirmation link. Please sign up again.')
            return redirect(url_for('signup'))
        
        pending_doc = pending_docs[0]
        pending_data = pending_doc.to_dict()
        
        # Check if token is expired
        current_time = datetime.now(timezone.utc)
        expires_at = pending_data['token_expires_at']
        
        # Handle timezone conversion
        if hasattr(expires_at, 'timestamp'):
            expires_at_dt = expires_at.replace(tzinfo=timezone.utc)
        elif isinstance(expires_at, datetime):
            if expires_at.tzinfo is None:
                expires_at_dt = expires_at.replace(tzinfo=timezone.utc)
            else:
                expires_at_dt = expires_at.astimezone(timezone.utc)
        else:
            expires_at_dt = datetime.fromisoformat(str(expires_at)).replace(tzinfo=timezone.utc)
        
        if current_time > expires_at_dt:
            # Delete expired pending user
            pending_doc.reference.delete()
            flash('Confirmation link has expired. Please sign up again.')
            return redirect(url_for('signup'))
        
        # Move user from pending_users to users collection
        user_data = {
            'username': pending_data['username'],
            'email': pending_data['email'],
            'password': pending_data['password'],
            'role': pending_data['role'],
            'is_verified': True,
            'created_at': pending_data['created_at'],
            'verified_at': current_time
        }
        
        # Add to users collection
        users_ref = db.collection('users')
        users_ref.add(user_data)
        
        # Delete from pending_users collection
        pending_doc.reference.delete()
        
        flash(f'Email confirmed successfully! Welcome to Quizera, {pending_data["username"]}! You can now log in.')
        return redirect(url_for('login'))
        
    except Exception as e:
        print(f"Error confirming email: {e}")
        flash('An error occurred during email confirmation. Please try again or contact support.')
        return redirect(url_for('signup'))

# Add a cleanup route for expired pending users (run this periodically)
@app.route('/admin/cleanup-pending-users', methods=['POST'])
def cleanup_pending_users():
    """Admin route to clean up expired pending user registrations"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        current_time = datetime.now(timezone.utc)
        
        # Delete expired pending users
        pending_users_ref = db.collection('pending_users')
        expired_docs = list(pending_users_ref.where('token_expires_at', '<', current_time).get())
        
        deleted_count = 0
        for doc in expired_docs:
            doc.reference.delete()
            deleted_count += 1
        
        return jsonify({
            'success': True, 
            'message': f'Cleaned up {deleted_count} expired pending registrations'
        })
        
    except Exception as e:
        return jsonify({
            'success': False, 
            'message': f'Error cleaning up pending users: {e}'
        }), 500

# Optional: Add a route to resend confirmation email
@app.route('/resend-confirmation', methods=['GET', 'POST'])
def resend_confirmation():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if not email:
            flash('Please enter your email address.')
            return render_template('resend_confirmation.html')
        
        try:
            # Find pending user
            pending_users_ref = db.collection('pending_users')
            pending_docs = list(pending_users_ref.where('email', '==', email).where('is_verified', '==', False).get())
            
            if not pending_docs:
                flash('No pending registration found for this email address.')
                return render_template('resend_confirmation.html')
            
            pending_doc = pending_docs[0]
            pending_data = pending_doc.to_dict()
            
            # Generate new confirmation token
            confirmation_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(confirmation_token.encode()).hexdigest()
            
            # Update token expiration (24 hours from now)
            current_time = datetime.now(timezone.utc)
            expires_at = current_time + timedelta(hours=24)
            
            # Update pending user with new token
            pending_doc.reference.update({
                'verification_token_hash': token_hash,
                'token_expires_at': expires_at
            })
            
            # Send confirmation email
            confirmation_url = url_for('confirm_email', token=confirmation_token, _external=True)
            username = pending_data['username']
            role = pending_data['role']
            
            msg = Message(
                'Quizera - Confirmation Email Resent',
                recipients=[email],
                html=f'''
                <html>
                <body>
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <div style="background-color: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
                            <h1 style="margin: 0; font-size: 28px;">Confirm Your Email</h1>
                        </div>
                        <div style="padding: 30px; border: 1px solid #e5e5e5; border-radius: 0 0 10px 10px;">
                            <p>Hello {username},</p>
                            <p>You requested a new confirmation email for your Quizera account. Please click the button below to confirm your email address:</p>
                            
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{confirmation_url}" 
                                   style="background-color: #2563eb; color: white; padding: 15px 30px; 
                                          text-decoration: none; border-radius: 8px; display: inline-block;
                                          font-weight: bold; font-size: 16px;">
                                    Confirm Email Address
                                </a>
                            </div>
                            
                            <p>This link will expire in 24 hours.</p>
                        </div>
                    </div>
                </body>
                </html>
                '''
            )
            
            mail.send(msg)
            flash('Confirmation email has been resent. Please check your email.')
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Error resending confirmation: {e}")
            flash('An error occurred. Please try again later.')
    
    return render_template('resend_confirmation.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['password']
        
#         # Find user by email
#         users_ref = db.collection('users')
#         user_docs = users_ref.where('email', '==', email).get()
        
#         if not user_docs:
#             flash('Invalid email or password.')
#             return render_template('login.html')
        
#         user_doc = user_docs[0]
#         user_data = user_doc.to_dict()
        
#         # Check password
#         if check_password_hash(user_data['password'], password):
#             # Store user info in session
#             session['user_id'] = user_doc.id
#             session['username'] = user_data['username']
#             session['email'] = user_data['email']
#             session['role'] = user_data['role']
            
#             flash(f'Welcome back, {user_data["username"]}!')
#             return redirect(url_for('dashboard'))
#         else:
#             flash('Invalid email or password.')
#             return render_template('login.html')
    
#     return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Find user by email
        users_ref = db.collection('users')
        user_docs = users_ref.where('email', '==', email).get()
        
        if not user_docs:
            # Check if user is in pending_users (not yet verified)
            pending_users_ref = db.collection('pending_users')
            pending_docs = list(pending_users_ref.where('email', '==', email).get())
            
            if pending_docs:
                flash('Please check your email and click the confirmation link to activate your account. <a href="/resend-confirmation" class="text-blue-600 hover:text-blue-800">Resend confirmation email</a>')
            else:
                flash('Invalid email or password.')
            return render_template('login.html')
        
        user_doc = user_docs[0]
        user_data = user_doc.to_dict()
        
        # Check if user is verified
        if not user_data.get('is_verified', True):  # Default to True for existing users
            flash('Please confirm your email address before logging in. <a href="/resend-confirmation" class="text-blue-600 hover:text-blue-800">Resend confirmation email</a>')
            return render_template('login.html')
        
        # Check password
        if check_password_hash(user_data['password'], password):
            # Store user info in session
            session['user_id'] = user_doc.id
            session['username'] = user_data['username']
            session['email'] = user_data['email']
            session['role'] = user_data['role']
            
            flash(f'Welcome back, {user_data["username"]}!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.')
            return render_template('login.html')
    
    return render_template('login.html')

# @app.route('/profile')
# def profile():
#     if 'user_id' not in session:
#         flash('Please log in to view your profile.')
#         return redirect(url_for('login'))
    
#     user_id = session['user_id']
#     username = session['username']
#     email = session['email']
#     role = session['role']
    
#     return render_template('profile.html', 
#                          username=username, 
#                          email=email, 
#                          role=role)

# @app.route('/profile', methods=['GET', 'POST'])
# def profile():
#     if 'user_id' not in session:
#         flash('Please log in to view your profile.')
#         return redirect(url_for('login'))
    
#     user_id = session['user_id']
    
#     # Get user data from Firestore
#     try:
#         user_doc = db.collection('users').document(user_id).get()
#         if not user_doc.exists:
#             flash('User profile not found.')
#             return redirect(url_for('login'))
        
#         user_data = user_doc.to_dict()
#         user_data['id'] = user_doc.id
        
#         # Handle POST request for profile updates
#         if request.method == 'POST':
#             # Update profile information
#             updated_data = {}
            
#             # Basic profile fields
#             if request.form.get('username'):
#                 updated_data['username'] = request.form['username']
#                 session['username'] = request.form['username']  # Update session
            
#             if request.form.get('full_name'):
#                 updated_data['full_name'] = request.form['full_name']
            
#             if request.form.get('email'):
#                 updated_data['email'] = request.form['email']
#                 session['email'] = request.form['email']  # Update session
            
#             if request.form.get('bio'):
#                 updated_data['bio'] = request.form['bio']
            
#             if request.form.get('institution'):
#                 updated_data['institution'] = request.form['institution']
            
#             # Handle password change
#             current_password = request.form.get('current_password')
#             new_password = request.form.get('new_password')
#             confirm_new_password = request.form.get('confirm_new_password')
            
#             if current_password and new_password:
#                 if check_password_hash(user_data['password'], current_password):
#                     if new_password == confirm_new_password:
#                         updated_data['password'] = generate_password_hash(new_password)
#                         flash('Password updated successfully!', 'success')
#                     else:
#                         flash('New passwords do not match.', 'error')
#                         return redirect(url_for('profile'))
#                 else:
#                     flash('Current password is incorrect.', 'error')
#                     return redirect(url_for('profile'))
            
#             # Update user document
#             if updated_data:
#                 updated_data['updated_at'] = datetime.now()
#                 db.collection('users').document(user_id).update(updated_data)
#                 flash('Profile updated successfully!', 'success')
#                 return redirect(url_for('profile'))
        
#         # Create a proper user object with default values for missing properties
#         class UserProfile:
#             def __init__(self, data):
#                 self.id = data.get('id')
#                 self.username = data.get('username', '')
#                 self.email = data.get('email', '')
#                 self.role = data.get('role', '')
#                 self.full_name = data.get('full_name', '')
#                 self.bio = data.get('bio', '')
#                 self.institution = data.get('institution', '')
#                 self.profile_picture = data.get('profile_picture', None)
#                 self.created_at = data.get('created_at', None)
#                 self.updated_at = data.get('updated_at', None)
        
#         user = UserProfile(user_data)
        
#         # Get user statistics
#         stats = {}
#         recent_activities = []
        
#         try:
#             if user_data['role'] == 'teacher':
#                 # Calculate teacher statistics
#                 subjects_query = db.collection('subjects').where('teacher_id', '==', user_id)
#                 subjects_docs = list(subjects_query.stream())
#                 subjects_count = len(subjects_docs)
                
#                 quizzes_query = db.collection('quizzes').where('teacher_id', '==', user_id)
#                 quizzes_docs = list(quizzes_query.stream())
#                 quizzes_count = len(quizzes_docs)
                
#                 # Calculate topics count
#                 topics_count = 0
#                 for subject_doc in subjects_docs:
#                     subject_data = subject_doc.to_dict()
#                     topics_count += subject_data.get('topic_count', 0)
                
#                 # Calculate quiz attempts and student engagement
#                 total_attempts = 0
#                 total_score = 0
#                 unique_students = set()
                
#                 for quiz_doc in quizzes_docs:
#                     quiz_id = quiz_doc.id
#                     attempts_query = db.collection('quiz_attempts').where('quiz_id', '==', quiz_id)
#                     attempts_docs = list(attempts_query.stream())
                    
#                     for attempt_doc in attempts_docs:
#                         attempt_data = attempt_doc.to_dict()
#                         total_attempts += 1
#                         total_score += attempt_data.get('percentage', 0)
#                         unique_students.add(attempt_data.get('user_id'))
                
#                 avg_score = (total_score / total_attempts) if total_attempts > 0 else 0
#                 total_students = len(unique_students)
                
#                 stats = {
#                     'subjects_count': subjects_count,
#                     'quizzes_count': quizzes_count,
#                     'topics_count': topics_count,
#                     'total_students': total_students,
#                     'avg_completion_rate': 85,  # Placeholder - calculate based on your needs
#                     'total_attempts': total_attempts,
#                     'avg_score': round(avg_score, 1),
#                     'active_students': total_students,
#                     'monthly_views': total_attempts * 3,  # Rough estimate
#                     'teaching_hours': topics_count * 2  # Rough estimate
#                 }
#             else:
#                 # Calculate student statistics
#                 attempts_query = db.collection('quiz_attempts').where('user_id', '==', user_id)
#                 attempts_docs = list(attempts_query.stream())
                
#                 quizzes_taken = len(attempts_docs)
#                 total_score = sum(attempt.to_dict().get('percentage', 0) for attempt in attempts_docs)
#                 average_score = (total_score / quizzes_taken) if quizzes_taken > 0 else 0
                
#                 # Get unique subjects from taken quizzes
#                 unique_subjects = set()
#                 for attempt_doc in attempts_docs:
#                     attempt_data = attempt_doc.to_dict()
#                     quiz_id = attempt_data.get('quiz_id')
#                     if quiz_id:
#                         quiz_doc = db.collection('quizzes').document(quiz_id).get()
#                         if quiz_doc.exists:
#                             quiz_data = quiz_doc.to_dict()
#                             subject_id = quiz_data.get('subject_id')
#                             if subject_id:
#                                 unique_subjects.add(subject_id)
                
#                 stats = {
#                     'quizzes_taken': quizzes_taken,
#                     'average_score': round(average_score, 1),
#                     'subjects_enrolled': len(unique_subjects),
#                     'study_hours': quizzes_taken * 0.5  # Rough estimate
#                 }
                
#         except Exception as e:
#             print(f"Error calculating stats: {e}")
#             # Provide default empty stats
#             if user_data['role'] == 'teacher':
#                 stats = {
#                     'subjects_count': 0,
#                     'quizzes_count': 0,
#                     'topics_count': 0,
#                     'total_students': 0,
#                     'avg_completion_rate': 0,
#                     'total_attempts': 0,
#                     'avg_score': 0,
#                     'active_students': 0,
#                     'monthly_views': 0,
#                     'teaching_hours': 0
#                 }
#             else:
#                 stats = {
#                     'quizzes_taken': 0,
#                     'average_score': 0,
#                     'subjects_enrolled': 0,
#                     'study_hours': 0
#                 }
        
#         return render_template('profile.html', 
#                              user=user,
#                              username=user.username,
#                              role=user.role,
#                              stats=stats,
#                              recent_activities=recent_activities)
    
#     except Exception as e:
#         print(f"Error loading profile: {e}")
#         flash('Error loading profile.')
#         return redirect(url_for('dashboard'))
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Please log in to view your profile.')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    print(f"Loading profile for user_id: {user_id}")  # Debug line
    
    # Get user data from Firestore
    try:
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            print(f"User document not found for user_id: {user_id}")  # Debug line
            flash('User profile not found.')
            return redirect(url_for('login'))
        
        user_data = user_doc.to_dict()
        user_data['id'] = user_doc.id
        print(f"User data loaded: {user_data.keys()}")  # Debug line
        
        # Handle POST request for profile updates
        if request.method == 'POST':
            # Update profile information
            updated_data = {}
            
            # Basic profile fields
            if request.form.get('username'):
                updated_data['username'] = request.form['username']
                session['username'] = request.form['username']  # Update session
            
            if request.form.get('full_name'):
                updated_data['full_name'] = request.form['full_name']
            
            if request.form.get('email'):
                updated_data['email'] = request.form['email']
                session['email'] = request.form['email']  # Update session
            
            if request.form.get('bio'):
                updated_data['bio'] = request.form['bio']
            
            if request.form.get('institution'):
                updated_data['institution'] = request.form['institution']
            
            # Handle avatar update
            avatar_type = request.form.get('avatar_type')
            avatar_id = request.form.get('avatar_id')
            if avatar_type and avatar_id:
                updated_data['avatar_type'] = avatar_type
                updated_data['avatar_id'] = avatar_id
            
            # Handle password change
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_new_password = request.form.get('confirm_new_password')
            
            if current_password and new_password:
                if check_password_hash(user_data['password'], current_password):
                    if new_password == confirm_new_password:
                        if len(new_password) >= 6:
                            updated_data['password'] = generate_password_hash(new_password)
                            flash('Password updated successfully!', 'success')
                        else:
                            flash('Password must be at least 6 characters long.', 'error')
                            return redirect(url_for('profile'))
                    else:
                        flash('New passwords do not match.', 'error')
                        return redirect(url_for('profile'))
                else:
                    flash('Current password is incorrect.', 'error')
                    return redirect(url_for('profile'))
            
            # Update user document
            if updated_data:
                updated_data['updated_at'] = datetime.now()
                db.collection('users').document(user_id).update(updated_data)
                flash('Profile updated successfully!', 'success')
                return redirect(url_for('profile'))
        
        # Create a proper user object with default values for missing properties
        class UserProfile:
            def __init__(self, data):
                self.id = data.get('id')
                self.username = data.get('username', '')
                self.email = data.get('email', '')
                self.role = data.get('role', '')
                self.full_name = data.get('full_name', '')
                self.bio = data.get('bio', '')
                self.institution = data.get('institution', '')
                self.profile_picture = data.get('profile_picture', None)
                self.avatar_type = data.get('avatar_type', 'initial')
                self.avatar_id = data.get('avatar_id', 'blue')
                self.created_at = data.get('created_at', None)
                self.updated_at = data.get('updated_at', None)
        
        user = UserProfile(user_data)
        print(f"UserProfile created with avatar_type: {user.avatar_type}, avatar_id: {user.avatar_id}")  # Debug line
        
        # Get user statistics and recent activities
        stats = {}
        recent_activities = []
        
        try:
            if user_data['role'] == 'teacher':
                # Calculate teacher statistics
                subjects_query = db.collection('subjects').where('teacher_id', '==', user_id)
                subjects_docs = list(subjects_query.stream())
                subjects_count = len(subjects_docs)
                
                quizzes_query = db.collection('quizzes').where('teacher_id', '==', user_id)
                quizzes_docs = list(quizzes_query.stream())
                quizzes_count = len(quizzes_docs)
                
                # Calculate topics count
                topics_count = 0
                for subject_doc in subjects_docs:
                    subject_data = subject_doc.to_dict()
                    topics_count += subject_data.get('topic_count', 0)
                
                # Calculate quiz attempts and student engagement
                total_attempts = 0
                total_score = 0
                unique_students = set()
                
                for quiz_doc in quizzes_docs:
                    quiz_id = quiz_doc.id
                    attempts_query = db.collection('quiz_attempts').where('quiz_id', '==', quiz_id)
                    attempts_docs = list(attempts_query.stream())
                    
                    for attempt_doc in attempts_docs:
                        attempt_data = attempt_doc.to_dict()
                        total_attempts += 1
                        total_score += attempt_data.get('percentage', 0)
                        unique_students.add(attempt_data.get('user_id'))
                
                # Get enrolled students count from enrollments collection
                enrollments_query = db.collection('enrollments').where('teacher_id', '==', user_id).where('status', '==', 'active')
                enrolled_students_docs = list(enrollments_query.stream())
                total_students = len(set(doc.to_dict()['student_id'] for doc in enrolled_students_docs))
                
                avg_score = (total_score / total_attempts) if total_attempts > 0 else 0
                
                stats = {
                    'subjects_count': subjects_count,
                    'quizzes_count': quizzes_count,
                    'topics_count': topics_count,
                    'total_students': total_students,
                    'avg_completion_rate': 85,  # Placeholder - calculate based on your needs
                    'total_attempts': total_attempts,
                    'avg_score': round(avg_score, 1),
                    'active_students': total_students,
                    'monthly_views': total_attempts * 3,  # Rough estimate
                    'teaching_hours': topics_count * 2  # Rough estimate
                }
                
                # Get recent activities for teachers
                recent_activities = get_teacher_recent_activities(user_id)
                
            else:
                # Calculate student statistics - UPDATED to use enrollments
                attempts_query = db.collection('quiz_attempts').where('user_id', '==', user_id)
                attempts_docs = list(attempts_query.stream())
                
                quizzes_taken = len(attempts_docs)
                total_score = sum(attempt.to_dict().get('percentage', 0) for attempt in attempts_docs)
                average_score = (total_score / quizzes_taken) if quizzes_taken > 0 else 0
                
                # Get subjects enrolled from enrollments collection (FIXED)
                enrollments_query = db.collection('enrollments').where('student_id', '==', user_id).where('status', '==', 'active')
                enrollments_docs = list(enrollments_query.stream())
                subjects_enrolled = len(enrollments_docs)
                
                stats = {
                    'quizzes_taken': quizzes_taken,
                    'average_score': round(average_score, 1),
                    'subjects_enrolled': subjects_enrolled,  # Now correctly reflects actual enrollments
                    'study_hours': quizzes_taken * 0.5  # Rough estimate
                }
                
                # Get recent activities for students
                recent_activities = get_student_recent_activities(user_id)
                
        except Exception as e:
            print(f"Error calculating stats: {e}")
            import traceback
            traceback.print_exc()
            # Provide default empty stats
            if user_data['role'] == 'teacher':
                stats = {
                    'subjects_count': 0,
                    'quizzes_count': 0,
                    'topics_count': 0,
                    'total_students': 0,
                    'avg_completion_rate': 0,
                    'total_attempts': 0,
                    'avg_score': 0,
                    'active_students': 0,
                    'monthly_views': 0,
                    'teaching_hours': 0
                }
            else:
                stats = {
                    'quizzes_taken': 0,
                    'average_score': 0,
                    'subjects_enrolled': 0,
                    'study_hours': 0
                }
        
        return render_template('profile.html', 
                             user=user,
                             username=user.username,
                             role=user.role,
                             stats=stats,
                             recent_activities=recent_activities)
    
    except Exception as e:
        print(f"Error loading profile: {e}")
        import traceback
        traceback.print_exc()  # Print full error traceback
        flash('Error loading profile.')
        return redirect(url_for('dashboard'))

# Helper functions to get recent activities
def get_teacher_recent_activities(teacher_id, limit=5):
    """Get recent activities for teachers"""
    activities = []
    try:
        # Get recent enrollments
        recent_enrollments = db.collection('enrollments')\
            .where('teacher_id', '==', teacher_id)\
            .order_by('enrolled_at', direction=firestore.Query.DESCENDING)\
            .limit(limit).stream()
        
        for enrollment in recent_enrollments:
            data = enrollment.to_dict()
            activities.append({
                'description': f"New student {data['student_name']} enrolled in {data['subject_name']}",
                'created_at': data['enrolled_at']
            })
        
        # Get recent quiz attempts on teacher's quizzes
        teacher_quizzes = db.collection('quizzes').where('teacher_id', '==', teacher_id).stream()
        quiz_ids = [quiz.id for quiz in teacher_quizzes]
        
        if quiz_ids:
            for quiz_id in quiz_ids[:3]:  # Limit to prevent too many queries
                recent_attempts = db.collection('quiz_attempts')\
                    .where('quiz_id', '==', quiz_id)\
                    .order_by('created_at', direction=firestore.Query.DESCENDING)\
                    .limit(2).stream()
                
                for attempt in recent_attempts:
                    data = attempt.to_dict()
                    activities.append({
                        'description': f"Student completed quiz with {data.get('percentage', 0)}% score",
                        'created_at': data.get('created_at', datetime.now())
                    })
        
        # Sort activities by date and limit
        activities.sort(key=lambda x: x['created_at'], reverse=True)
        return activities[:limit]
        
    except Exception as e:
        print(f"Error getting teacher activities: {e}")
        return []

def get_student_recent_activities(student_id, limit=5):
    """Get recent activities for students"""
    activities = []
    try:
        # Get recent enrollments
        recent_enrollments = db.collection('enrollments')\
            .where('student_id', '==', student_id)\
            .order_by('enrolled_at', direction=firestore.Query.DESCENDING)\
            .limit(limit).stream()
        
        for enrollment in recent_enrollments:
            data = enrollment.to_dict()
            activities.append({
                'description': f"Enrolled in {data['subject_name']} by {data['teacher_name']}",
                'created_at': data['enrolled_at']
            })
        
        # Get recent quiz attempts
        recent_attempts = db.collection('quiz_attempts')\
            .where('user_id', '==', student_id)\
            .order_by('created_at', direction=firestore.Query.DESCENDING)\
            .limit(limit).stream()
        
        for attempt in recent_attempts:
            data = attempt.to_dict()
            activities.append({
                'description': f"Completed quiz with {data.get('percentage', 0)}% score",
                'created_at': data.get('created_at', datetime.now())
            })
        
        # Sort activities by date and limit
        activities.sort(key=lambda x: x['created_at'], reverse=True)
        return activities[:limit]
        
    except Exception as e:
        print(f"Error getting student activities: {e}")
        return []

# @app.route('/dashboard')
# def dashboard():
#     if 'user_id' not in session:
#         flash('Please log in to access your dashboard.')
#         return redirect(url_for('login'))
    
#     user_role = session.get('role')
#     username = session.get('username')
    
#     if user_role == 'teacher':
#         # Get teacher's subjects and quizzes (existing code remains the same)
#         subjects = []
#         quizzes = []
#         try:
#             subjects_ref = db.collection('subjects').where('teacher_id', '==', session['user_id'])
#             for doc in subjects_ref.stream():
#                 subject_data = doc.to_dict()
#                 subject_data['id'] = doc.id
                
#                 # Calculate topic count for each subject
#                 topics_ref = db.collection('topics').where('subject_id', '==', doc.id)
#                 topic_count = len(list(topics_ref.stream()))
#                 subject_data['topic_count'] = topic_count
                
#                 subjects.append(subject_data)
                
#             quizzes_ref = db.collection('quizzes').where('teacher_id', '==', session['user_id'])
#             for doc in quizzes_ref.stream():
#                 quiz_data = doc.to_dict()
#                 quiz_data['id'] = doc.id
#                 quizzes.append(quiz_data)
#         except Exception as e:
#             print(f"Error fetching teacher data: {e}")
        
#         return render_template('dashboard.html', role='teacher', username=username, subjects=subjects, quizzes=quizzes)
    
#     elif user_role == 'student':
#         # Get student's enrolled subjects and available subjects
#         enrolled_subjects = []
#         available_subjects = []
#         enrolled_quizzes = []
        
#         try:
#             # Get enrolled subjects
#             enrollments_ref = db.collection('enrollments').where('student_id', '==', session['user_id'])
#             enrolled_subject_ids = []
            
#             for doc in enrollments_ref.stream():
#                 enrollment_data = doc.to_dict()
#                 subject_id = enrollment_data['subject_id']
#                 enrolled_subject_ids.append(subject_id)
                
#                 # Get subject details
#                 subject_ref = db.collection('subjects').document(subject_id)
#                 subject_doc = subject_ref.get()
                
#                 if subject_doc.exists:
#                     subject_data = subject_doc.to_dict()
#                     subject_data['id'] = subject_doc.id
                    
#                     # Calculate topic count
#                     topics_ref = db.collection('topics').where('subject_id', '==', subject_id)
#                     topic_count = len(list(topics_ref.stream()))
#                     subject_data['topic_count'] = topic_count
#                     subject_data['enrollment_date'] = enrollment_data['enrolled_at']
                    
#                     enrolled_subjects.append(subject_data)
            
#             # Get available subjects (not enrolled)
#             all_subjects_ref = db.collection('subjects')
#             for doc in all_subjects_ref.stream():
#                 if doc.id not in enrolled_subject_ids:
#                     subject_data = doc.to_dict()
#                     subject_data['id'] = doc.id
                    
#                     # Calculate topic count
#                     topics_ref = db.collection('topics').where('subject_id', '==', doc.id)
#                     topic_count = len(list(topics_ref.stream()))
#                     subject_data['topic_count'] = topic_count
                    
#                     available_subjects.append(subject_data)
            
#             # Get quizzes from enrolled subjects
#             for subject_id in enrolled_subject_ids:
#                 quizzes_ref = db.collection('quizzes').where('subject_id', '==', subject_id).where('is_published', '==', True)
#                 for doc in quizzes_ref.stream():
#                     quiz_data = doc.to_dict()
#                     quiz_data['id'] = doc.id
#                     enrolled_quizzes.append(quiz_data)
                    
#         except Exception as e:
#             print(f"Error fetching student data: {e}")
        
#         return render_template('dashboard.html', 
#                              role='student', 
#                              username=username, 
#                              enrolled_subjects=enrolled_subjects,
#                              available_subjects=available_subjects, 
#                              quizzes=enrolled_quizzes)
    
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access your dashboard.')
        return redirect(url_for('login'))
    
    user_role = session.get('role')
    username = session.get('username')
    
    if user_role == 'teacher':
        # Get teacher's subjects and quizzes (existing code remains the same)
        subjects = []
        quizzes = []
        try:
            subjects_ref = db.collection('subjects').where('teacher_id', '==', session['user_id'])
            for doc in subjects_ref.stream():
                subject_data = doc.to_dict()
                subject_data['id'] = doc.id
                
                # Calculate topic count for each subject
                topics_ref = db.collection('topics').where('subject_id', '==', doc.id)
                topic_count = len(list(topics_ref.stream()))
                subject_data['topic_count'] = topic_count
                
                subjects.append(subject_data)
                
            quizzes_ref = db.collection('quizzes').where('teacher_id', '==', session['user_id'])
            for doc in quizzes_ref.stream():
                quiz_data = doc.to_dict()
                quiz_data['id'] = doc.id
                quizzes.append(quiz_data)
        except Exception as e:
            print(f"Error fetching teacher data: {e}")
        
        return render_template('dashboard.html', role='teacher', username=username, subjects=subjects, quizzes=quizzes)
    
    elif user_role == 'student':
        # Get student's enrolled subjects only (FIXED)
        enrolled_subjects = []
        enrolled_quizzes = []
        
        try:
            # Get ONLY ACTIVE enrolled subjects
            enrollments_ref = db.collection('enrollments').where('student_id', '==', session['user_id']).where('status', '==', 'active')
            enrolled_subject_ids = []
            
            for doc in enrollments_ref.stream():
                enrollment_data = doc.to_dict()
                subject_id = enrollment_data['subject_id']
                enrolled_subject_ids.append(subject_id)
                
                # Get subject details
                subject_ref = db.collection('subjects').document(subject_id)
                subject_doc = subject_ref.get()
                
                if subject_doc.exists:
                    subject_data = subject_doc.to_dict()
                    subject_data['id'] = subject_doc.id
                    
                    # Get teacher name from subject data
                    subject_data['teacher_name'] = subject_data.get('teacher_name', 'Unknown Teacher')
                    
                    # Calculate topic count
                    topics_ref = db.collection('topics').where('subject_id', '==', subject_id)
                    topic_count = len(list(topics_ref.stream()))
                    subject_data['topic_count'] = topic_count
                    subject_data['enrollment_date'] = enrollment_data.get('enrolled_at')
                    
                    enrolled_subjects.append(subject_data)
            
            # Get quizzes ONLY from enrolled subjects (FIXED)
            for subject_id in enrolled_subject_ids:
                quizzes_ref = db.collection('quizzes').where('subject_id', '==', subject_id).where('is_published', '==', True)
                for doc in quizzes_ref.stream():
                    quiz_data = doc.to_dict()
                    quiz_data['id'] = doc.id
                    
                    # Get subject name for the quiz
                    subject_ref = db.collection('subjects').document(subject_id)
                    subject_doc = subject_ref.get()
                    if subject_doc.exists:
                        quiz_data['subject_name'] = subject_doc.to_dict().get('name', 'Unknown Subject')
                    
                    # Get question count
                    questions_ref = db.collection('questions').where('quiz_id', '==', doc.id)
                    question_count = len(list(questions_ref.stream()))
                    quiz_data['question_count'] = question_count
                    
                    enrolled_quizzes.append(quiz_data)
                    
        except Exception as e:
            print(f"Error fetching student data: {e}")
            import traceback
            traceback.print_exc()
        
        # Return ONLY enrolled subjects and their quizzes - NO available_subjects
        return render_template('dashboard.html', 
                             role='student', 
                             username=username, 
                             enrolled_subjects=enrolled_subjects,
                             quizzes=enrolled_quizzes)
    
# Subject Management Routes
@app.route('/create-subject', methods=['GET', 'POST'])
def create_subject():
    if 'user_id' not in session or session.get('role') != 'teacher':
        flash('Access denied. Teachers only.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        
        subject_data = {
            'name': name,
            'description': description,
            'teacher_id': session['user_id'],
            'teacher_name': session['username'],
            'created_at': datetime.now(),
            'topic_count': 0
        }
        
        try:
            db.collection('subjects').add(subject_data)
            flash('Subject created successfully!')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Error creating subject: {e}')
    
    return render_template('create_subject.html', username=session.get('username'), role=session.get('role'))

# Helper function to get student's completed topics
def get_student_completed_topics(student_id, subject_id=None):
    """Get list of topic IDs that student has completed"""
    try:
        query = db.collection('topic_completions').where('student_id', '==', student_id)
        if subject_id:
            query = query.where('subject_id', '==', subject_id)
        
        completed_topics = []
        for doc in query.stream():
            completed_topics.append(doc.to_dict()['topic_id'])
        return completed_topics
    except Exception as e:
        print(f"Error getting completed topics: {e}")
        return []

# Helper function to calculate subject progress
def calculate_subject_progress(student_id, subject_id):
    """Calculate completion percentage for a subject"""
    try:
        # Get total topics in subject
        total_topics = db.collection('topics').where('subject_id', '==', subject_id).stream()
        total_count = len(list(total_topics))
        
        if total_count == 0:
            return 0
        
        # Get completed topics for this subject
        completed_topics = get_student_completed_topics(student_id, subject_id)
        completed_count = len(completed_topics)
        
        progress_percentage = (completed_count / total_count) * 100
        return round(progress_percentage, 1)
    except Exception as e:
        print(f"Error calculating progress: {e}")
        return 0

# Route to mark topic as completed
@app.route('/topic/<topic_id>/complete', methods=['POST'])
def mark_topic_complete(topic_id):
    if 'user_id' not in session or session.get('role') != 'student':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        # Get topic details
        topic_ref = db.collection('topics').document(topic_id)
        topic_doc = topic_ref.get()
        
        if not topic_doc.exists:
            return jsonify({'success': False, 'message': 'Topic not found'}), 404
        
        topic_data = topic_doc.to_dict()
        subject_id = topic_data['subject_id']
        student_id = session['user_id']
        
        # Check if student is enrolled
        if not check_enrollment(student_id, subject_id):
            return jsonify({'success': False, 'message': 'Not enrolled in this subject'}), 403
        
        # Check if already completed
        existing_completion = db.collection('topic_completions').where('student_id', '==', student_id).where('topic_id', '==', topic_id).limit(1).stream()
        if len(list(existing_completion)) > 0:
            return jsonify({'success': False, 'message': 'Topic already marked as completed'})
        
        # Mark as completed
        completion_data = {
            'student_id': student_id,
            'topic_id': topic_id,
            'subject_id': subject_id,
            'completed_at': datetime.now(),
            'student_name': session.get('username', 'Unknown')
        }
        
        db.collection('topic_completions').add(completion_data)
        
        # Calculate new progress percentage
        progress = calculate_subject_progress(student_id, subject_id)
        
        return jsonify({
            'success': True, 
            'message': 'Topic marked as completed!',
            'progress': progress
        })
        
    except Exception as e:
        print(f"Error marking topic complete: {e}")
        return jsonify({'success': False, 'message': 'Error marking topic as completed'}), 500

# Route to unmark topic as completed
@app.route('/topic/<topic_id>/uncomplete', methods=['POST'])
def unmark_topic_complete(topic_id):
    if 'user_id' not in session or session.get('role') != 'student':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        student_id = session['user_id']
        
        # Find and delete the completion record
        completions = db.collection('topic_completions').where('student_id', '==', student_id).where('topic_id', '==', topic_id).limit(1).stream()
        
        deleted = False
        subject_id = None
        for completion in completions:
            subject_id = completion.to_dict()['subject_id']
            completion.reference.delete()
            deleted = True
            break
        
        if not deleted:
            return jsonify({'success': False, 'message': 'Topic was not marked as completed'})
        
        # Calculate new progress percentage
        progress = calculate_subject_progress(student_id, subject_id) if subject_id else 0
        
        return jsonify({
            'success': True, 
            'message': 'Topic unmarked as completed',
            'progress': progress
        })
        
    except Exception as e:
        print(f"Error unmarking topic: {e}")
        return jsonify({'success': False, 'message': 'Error unmarking topic'}), 500

# @app.route('/subject/<subject_id>')
# def view_subject(subject_id):
#     if 'user_id' not in session:
#         flash('Please log in to view subjects.')
#         return redirect(url_for('login'))
    
#     try:
#         # Get subject details
#         subject_ref = db.collection('subjects').document(subject_id)
#         subject_doc = subject_ref.get()
        
#         if not subject_doc.exists:
#             flash('Subject not found.')
#             return redirect(url_for('dashboard'))
        
#         subject_data = subject_doc.to_dict()
#         subject_data['id'] = subject_doc.id
        
#         # Get topics for this subject
#         topics = []
#         topics_ref = db.collection('topics').where('subject_id', '==', subject_id).order_by('created_at')
#         for doc in topics_ref.stream():
#             topic_data = doc.to_dict()
#             topic_data['id'] = doc.id
#             topics.append(topic_data)
        
#         return render_template('subject_detail.html', subject=subject_data, topics=topics)
#     except Exception as e:
#         flash(f'Error loading subject: {e}')
#         return redirect(url_for('dashboard'))

@app.route('/subject/<subject_id>')
def view_subject(subject_id):
    if 'user_id' not in session:
        flash('Please log in to view subjects.')
        return redirect(url_for('login'))
    
    try:
        # Get subject details
        subject_ref = db.collection('subjects').document(subject_id)
        subject_doc = subject_ref.get()
        
        if not subject_doc.exists:
            flash('Subject not found.')
            return redirect(url_for('dashboard'))
        
        subject_data = subject_doc.to_dict()
        subject_data['id'] = subject_doc.id
        
        # Check enrollment for students
        is_enrolled = False
        progress = 0
        completed_topics = []
        
        if session.get('role') == 'student':
            is_enrolled = check_enrollment(session['user_id'], subject_id)
            if not is_enrolled:
                # Allow viewing subject info but not topics
                return render_template('subject_detail.html', 
                                     subject=subject_data, 
                                     topics=[], 
                                     is_enrolled=False, 
                                     enrollment_required=True,
                                     progress=0)
            else:
                # Calculate progress and get completed topics
                progress = calculate_subject_progress(session['user_id'], subject_id)
                completed_topics = get_student_completed_topics(session['user_id'], subject_id)
        
        # Teachers can always view their own subjects
        elif session.get('role') == 'teacher' and subject_data['teacher_id'] != session['user_id']:
            flash('Access denied.')
            return redirect(url_for('dashboard'))
        
        # Get topics for this subject (only if enrolled or teacher)
        topics = []
        if is_enrolled or session.get('role') == 'teacher':
            topics_ref = db.collection('topics').where('subject_id', '==', subject_id).order_by('created_at')
            for doc in topics_ref.stream():
                topic_data = doc.to_dict()
                topic_data['id'] = doc.id
                # Add completion status for students
                if session.get('role') == 'student':
                    topic_data['is_completed'] = doc.id in completed_topics
                topics.append(topic_data)
        
        return render_template('subject_detail.html', 
                             subject=subject_data, 
                             topics=topics, 
                             is_enrolled=is_enrolled,
                             progress=progress,
                             completed_topics=completed_topics,
                             username=session.get('username'),
                             role=session.get('role'),
                             user_id=session.get('user_id'))

    except Exception as e:
        flash(f'Error loading subject: {e}')
        return redirect(url_for('dashboard'))
@app.route('/topic/<topic_id>')
def view_topic(topic_id):
    if 'user_id' not in session:
        flash('Please log in to view topics.')
        return redirect(url_for('login'))
    
    try:
        topic_ref = db.collection('topics').document(topic_id)
        topic_doc = topic_ref.get()
        
        if not topic_doc.exists:
            flash('Topic not found.')
            return redirect(url_for('dashboard'))
        
        topic_data = topic_doc.to_dict()
        topic_data['id'] = topic_doc.id
        
        # Check enrollment for students
        is_completed = False
        if session.get('role') == 'student':
            is_enrolled = check_enrollment(session['user_id'], topic_data['subject_id'])
            if not is_enrolled:
                flash('You must be enrolled in this subject to view topics.')
                return redirect(url_for('view_subject', subject_id=topic_data['subject_id']))
            
            # Check if topic is completed by this student
            completed_topics = get_student_completed_topics(session['user_id'], topic_data['subject_id'])
            is_completed = topic_id in completed_topics
        
        # Check teacher ownership
        elif session.get('role') == 'teacher' and topic_data['teacher_id'] != session['user_id']:
            flash('Access denied.')
            return redirect(url_for('dashboard'))
        
        topic_data['is_completed'] = is_completed
        
        return render_template('topic_detail.html', 
                             topic=topic_data,
                             username=session.get('username'),
                             role=session.get('role'),
                             user_id=session.get('user_id'))
        
    except Exception as e:
        flash(f'Error loading topic: {e}')
        return redirect(url_for('dashboard'))
    

@app.route('/student/<student_id>/progress/<subject_id>')
def get_student_progress(student_id, subject_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Students can only view their own progress, teachers can view any student's progress
    if session.get('role') == 'student' and session['user_id'] != student_id:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        progress = calculate_subject_progress(student_id, subject_id)
        completed_topics = get_student_completed_topics(student_id, subject_id)
        
        # Get total topics count
        total_topics = db.collection('topics').where('subject_id', '==', subject_id).stream()
        total_count = len(list(total_topics))
        
        return jsonify({
            'progress': progress,
            'completed_count': len(completed_topics),
            'total_count': total_count,
            'completed_topics': completed_topics
        })
        
    except Exception as e:
        print(f"Error getting student progress: {e}")
        return jsonify({'error': 'Error fetching progress'}), 500

@app.route('/subject/<subject_id>/create-topic', methods=['GET', 'POST'])
def create_topic(subject_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        flash('Access denied. Teachers only.')
        return redirect(url_for('dashboard'))
    
    # Check if user owns this subject
    try:
        subject_ref = db.collection('subjects').document(subject_id)
        subject_doc = subject_ref.get()
        
        if not subject_doc.exists or subject_doc.to_dict()['teacher_id'] != session['user_id']:
            flash('Access denied.')
            return redirect(url_for('dashboard'))
    except Exception as e:
        flash('Error accessing subject.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        title = request.form['title']
        content_text = request.form.get('content_text', '')
        video_link = request.form.get('video_link', '')
        
        topic_data = {
            'subject_id': subject_id,
            'title': title,
            'content_text': content_text,
            'video_link': video_link,
            'created_at': datetime.now(),
            'teacher_id': session['user_id']
        }
        
        try:
            db.collection('topics').add(topic_data)
            
            # Update topic count in subject
            subject_ref.update({'topic_count': Increment(1)})
            
            flash('Topic created successfully!')
            return redirect(url_for('view_subject', subject_id=subject_id))
        except Exception as e:
            flash(f'Error creating topic: {e}')
    
    return render_template('create_topic.html', subject_id=subject_id, username=session.get('username'), role=session.get('role'))

# @app.route('/topic/<topic_id>')
# def view_topic(topic_id):
#     if 'user_id' not in session:
#         flash('Please log in to view topics.')
#         return redirect(url_for('login'))
    
#     try:
#         topic_ref = db.collection('topics').document(topic_id)
#         topic_doc = topic_ref.get()
        
#         if not topic_doc.exists:
#             flash('Topic not found.')
#             return redirect(url_for('dashboard'))
        
#         topic_data = topic_doc.to_dict()
#         topic_data['id'] = topic_doc.id
        
#         return render_template('topic_detail.html', topic=topic_data)
#     except Exception as e:
#         flash(f'Error loading topic: {e}')
#         return redirect(url_for('dashboard'))

# Updated view_topic route
# @app.route('/topic/<topic_id>')
# def view_topic(topic_id):
#     if 'user_id' not in session:
#         flash('Please log in to view topics.')
#         return redirect(url_for('login'))
    
#     try:
#         topic_ref = db.collection('topics').document(topic_id)
#         topic_doc = topic_ref.get()
        
#         if not topic_doc.exists:
#             flash('Topic not found.')
#             return redirect(url_for('dashboard'))
        
#         topic_data = topic_doc.to_dict()
#         topic_data['id'] = topic_doc.id
        
#         # Check enrollment for students
#         if session.get('role') == 'student':
#             is_enrolled = check_enrollment(session['user_id'], topic_data['subject_id'])
#             if not is_enrolled:
#                 flash('You must be enrolled in this subject to view topics.')
#                 return redirect(url_for('view_subject', subject_id=topic_data['subject_id']))
        
#         # Check teacher ownership
#         elif session.get('role') == 'teacher' and topic_data['teacher_id'] != session['user_id']:
#             flash('Access denied.')
#             return redirect(url_for('dashboard'))
        
#         return render_template('topic_detail.html', topic=topic_data)
        
#     except Exception as e:
#         flash(f'Error loading topic: {e}')
#         return redirect(url_for('dashboard'))

# Topic Edit and Delete Routes
@app.route('/topic/<topic_id>/edit', methods=['GET', 'POST'])
def edit_topic(topic_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        flash('Access denied. Teachers only.')
        return redirect(url_for('dashboard'))
    
    try:
        # Verify ownership
        topic_ref = db.collection('topics').document(topic_id)
        topic_doc = topic_ref.get()
        
        if not topic_doc.exists or topic_doc.to_dict()['teacher_id'] != session['user_id']:
            flash('Topic not found or access denied.')
            return redirect(url_for('dashboard'))
        
        topic_data = topic_doc.to_dict()
        topic_data['id'] = topic_doc.id
        
        if request.method == 'POST':
            # Handle topic update
            title = request.form.get('title', '').strip()
            content_text = request.form.get('content_text', '').strip()
            video_link = request.form.get('video_link', '').strip()
            
            if not title:
                flash('Topic title is required.')
                return render_template('edit_topic.html', topic=topic_data)
            
            update_data = {
                'title': title,
                'content_text': content_text,
                'video_link': video_link,
                'updated_at': datetime.now()
            }
            
            topic_ref.update(update_data)
            flash('Topic updated successfully!')
            return redirect(url_for('view_topic', topic_id=topic_id))
        
        return render_template('edit_topic.html', topic=topic_data)
        
    except Exception as e:
        flash(f'Error accessing topic: {e}')
        return redirect(url_for('dashboard'))

@app.route('/topic/<topic_id>/delete', methods=['POST'])
def delete_topic(topic_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        # Verify ownership
        topic_ref = db.collection('topics').document(topic_id)
        topic_doc = topic_ref.get()
        
        if not topic_doc.exists or topic_doc.to_dict()['teacher_id'] != session['user_id']:
            return jsonify({'success': False, 'message': 'Topic not found or access denied'}), 404
        
        topic_data = topic_doc.to_dict()
        subject_id = topic_data['subject_id']
        
        # Delete the topic
        topic_ref.delete()
        
        # Update topic count in subject
        subject_ref = db.collection('subjects').document(subject_id)
        subject_ref.update({'topic_count': Increment(-1)})
        
        return jsonify({'success': True, 'message': 'Topic deleted successfully'})
        
    except Exception as e:
        print(f"Error deleting topic: {e}")
        return jsonify({'success': False, 'message': 'Error deleting topic'}), 500

# Quiz Management Routes
@app.route('/create-quiz', methods=['GET', 'POST'])
def create_quiz():
    if 'user_id' not in session or session.get('role') != 'teacher':
        flash('Access denied. Teachers only.')
        return redirect(url_for('dashboard'))
    
    # Get teacher's subjects for dropdown
    subjects = []
    try:
        subjects_ref = db.collection('subjects').where('teacher_id', '==', session['user_id'])
        for doc in subjects_ref.stream():
            subject_data = doc.to_dict()
            subject_data['id'] = doc.id
            subjects.append(subject_data)
    except Exception as e:
        print(f"Error fetching subjects: {e}")
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        subject_id = request.form['subject_id']
        time_limit = int(request.form.get('time_limit', 30))
        
        # Get subject name
        subject_name = ''
        try:
            subject_doc = db.collection('subjects').document(subject_id).get()
            if subject_doc.exists:
                subject_name = subject_doc.to_dict()['name']
        except Exception as e:
            print(f"Error getting subject name: {e}")
        
        quiz_data = {
            'title': title,
            'description': description,
            'subject_id': subject_id,
            'subject_name': subject_name,
            'teacher_id': session['user_id'],
            'teacher_name': session['username'],
            'time_limit': time_limit,
            'created_at': datetime.now(),
            'question_count': 0,
            'is_published': False
        }
        
        try:
            doc_ref = db.collection('quizzes').add(quiz_data)
            quiz_id = doc_ref[1].id
            flash('Quiz created successfully! Now add questions.')
            return redirect(url_for('manage_quiz', quiz_id=quiz_id))
        except Exception as e:
            flash(f'Error creating quiz: {e}')
    
    return render_template('create_quiz.html', subjects=subjects, username=session.get('username'), role=session.get('role'))

@app.route('/quiz/<quiz_id>/manage')
def manage_quiz(quiz_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        flash('Access denied. Teachers only.')
        return redirect(url_for('dashboard'))
    
    try:
        # Get quiz details
        quiz_ref = db.collection('quizzes').document(quiz_id)
        quiz_doc = quiz_ref.get()
        
        if not quiz_doc.exists or quiz_doc.to_dict()['teacher_id'] != session['user_id']:
            flash('Quiz not found or access denied.')
            return redirect(url_for('dashboard'))
        
        quiz_data = quiz_doc.to_dict()
        quiz_data['id'] = quiz_doc.id
        
        # Get questions for this quiz
        questions = []
        questions_ref = db.collection('questions').where('quiz_id', '==', quiz_id).order_by('created_at')
        for doc in questions_ref.stream():
            question_data = doc.to_dict()
            question_data['id'] = doc.id
            questions.append(question_data)
        
        return render_template('manage_quiz.html', quiz=quiz_data, questions=questions, username=session.get('username'), role=session.get('role'))
    except Exception as e:
        flash(f'Error loading quiz: {e}')
        return redirect(url_for('dashboard'))

# @app.route('/quiz/<quiz_id>/add-question', methods=['GET', 'POST'])
# def add_question(quiz_id):
#     if 'user_id' not in session or session.get('role') != 'teacher':
#         flash('Access denied. Teachers only.')
#         return redirect(url_for('dashboard'))
    
#     # Verify quiz ownership
#     try:
#         quiz_ref = db.collection('quizzes').document(quiz_id)
#         quiz_doc = quiz_ref.get()
        
#         if not quiz_doc.exists or quiz_doc.to_dict()['teacher_id'] != session['user_id']:
#             flash('Quiz not found or access denied.')
#             return redirect(url_for('dashboard'))
        
#         quiz_data = quiz_doc.to_dict()
#     except Exception as e:
#         flash('Error accessing quiz.')
#         return redirect(url_for('dashboard'))
    
#     if request.method == 'POST':
#         question_type = request.form['question_type']
#         question_text = request.form['question_text']
#         points = int(request.form.get('points', 1))
        
#         question_data = {
#             'quiz_id': quiz_id,
#             'question_type': question_type,
#             'question_text': question_text,
#             'points': points,
#             'created_at': datetime.now()
#         }
        
#         # Handle different question types
#         if question_type == 'multiple_choice':
#             options = [
#                 request.form.get('option_a', ''),
#                 request.form.get('option_b', ''),
#                 request.form.get('option_c', ''),
#                 request.form.get('option_d', '')
#             ]
#             correct_answer = request.form['correct_answer']
#             question_data.update({
#                 'options': options,
#                 'correct_answer': correct_answer
#             })
        
#         elif question_type == 'true_false':
#             correct_answer = request.form['tf_answer'] == 'true'
#             question_data['correct_answer'] = correct_answer
        
#         elif question_type in ['identification', 'enumeration']:
#             correct_answers = [ans.strip() for ans in request.form['correct_answers'].split(',')]
#             question_data['correct_answers'] = correct_answers
        
#         try:
#             db.collection('questions').add(question_data)
            
#             # Update question count in quiz
#             quiz_ref.update({'question_count': Increment(1)})
            
#             flash('Question added successfully!')
#             return redirect(url_for('manage_quiz', quiz_id=quiz_id))
#         except Exception as e:
#             flash(f'Error adding question: {e}')
    
#     return render_template('add_question.html', quiz_id=quiz_id, quiz=quiz_data)

@app.route('/quiz/<quiz_id>/publish')
def publish_quiz(quiz_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        flash('Access denied. Teachers only.')
        return redirect(url_for('dashboard'))
    
    try:
        quiz_ref = db.collection('quizzes').document(quiz_id)
        quiz_doc = quiz_ref.get()
        
        if not quiz_doc.exists or quiz_doc.to_dict()['teacher_id'] != session['user_id']:
            flash('Quiz not found or access denied.')
            return redirect(url_for('dashboard'))
        
        quiz_ref.update({'is_published': True})
        flash('Quiz published successfully!')
        
    except Exception as e:
        flash(f'Error publishing quiz: {e}')
    
    return redirect(url_for('manage_quiz', quiz_id=quiz_id))


@app.route('/quiz/<quiz_id>/add-question', methods=['GET', 'POST'])
def add_question(quiz_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        flash('Access denied. Teachers only.')
        return redirect(url_for('dashboard'))
    
    # Verify quiz ownership
    try:
        quiz_ref = db.collection('quizzes').document(quiz_id)
        quiz_doc = quiz_ref.get()
        
        if not quiz_doc.exists or quiz_doc.to_dict()['teacher_id'] != session['user_id']:
            flash('Quiz not found or access denied.')
            return redirect(url_for('dashboard'))
        
        quiz_data = quiz_doc.to_dict()
    except Exception as e:
        flash('Error accessing quiz.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Handle JSON requests (CSV/Bulk import)
        if request.content_type == 'application/json' or request.form.get('method') in ['csv', 'bulk']:
            try:
                # Get data from JSON or form
                if request.is_json:
                    data = request.get_json()
                    method = data.get('method')
                    questions = data.get('questions', [])
                else:
                    method = request.form.get('method')
                    questions_json = request.form.get('questions')
                    questions = json.loads(questions_json) if questions_json else []
                
                if method in ['csv', 'bulk']:
                    added_count = 0
                    
                    for question in questions:
                        question_data = {
                            'quiz_id': quiz_id,
                            'question_type': question.get('type'),
                            'question_text': question.get('question') or question.get('text'),
                            'points': question.get('points', 1),
                            'created_at': datetime.now()
                        }
                        
                        # Handle different question types
                        q_type = question.get('type')
                        
                        if q_type == 'multiple_choice':
                            # Get choices from choicesArray or parse from choices string
                            choices = question.get('choicesArray', [])
                            if not choices and question.get('choices'):
                                choices = [choice.strip() for choice in question.get('choices').split('|')]
                            
                            if len(choices) >= 2:
                                # Pad with empty options if less than 4
                                while len(choices) < 4:
                                    choices.append('')
                                question_data['options'] = choices[:4]
                                
                                # Get correct answer
                                correct_answer = question.get('correct_answer', 'A')
                                # Convert index to letter if numeric
                                if correct_answer.isdigit():
                                    correct_index = int(correct_answer)
                                    if 0 <= correct_index < 4:
                                        correct_answer = chr(65 + correct_index)  # Convert 0->A, 1->B, etc.
                                    else:
                                        correct_answer = 'A'  # Default fallback
                                question_data['correct_answer'] = correct_answer
                            else:
                                # For CSV with old format compatibility
                                choices_from_bulk = question.get('choicesArray', [])
                                if choices_from_bulk and len(choices_from_bulk) >= 2:
                                    while len(choices_from_bulk) < 4:
                                        choices_from_bulk.append('')
                                    question_data['options'] = choices_from_bulk[:4]
                                    question_data['correct_answer'] = 'A'  # Default
                                else:
                                    continue
                        
                        elif q_type == 'true_false':
                            # Get correct answer from answers field
                            correct_answer = question.get('answers', question.get('correct_answer', 'true'))
                            
                            # Handle different types of correct_answer values
                            if isinstance(correct_answer, bool):
                                question_data['correct_answer'] = correct_answer
                            elif isinstance(correct_answer, str):
                                correct_answer_lower = correct_answer.lower()
                                if correct_answer_lower in ['true', '1', 'yes', 't']:
                                    question_data['correct_answer'] = True
                                else:
                                    question_data['correct_answer'] = False
                            elif isinstance(correct_answer, (int, float)):
                                question_data['correct_answer'] = bool(correct_answer)
                            else:
                                # Default fallback
                                question_data['correct_answer'] = True
                        
                        elif q_type in ['identification', 'enumeration']:
                            # Get answers from answersArray or parse from answers string
                            answers = question.get('answersArray', [])
                            if not answers and question.get('answers'):
                                answers_value = question.get('answers')
                                if isinstance(answers_value, str):
                                    answers = [answer.strip() for answer in answers_value.split('|')]
                                elif isinstance(answers_value, list):
                                    answers = [str(answer).strip() for answer in answers_value]
                            elif not answers and question.get('choices'):
                                # Fallback for bulk questions
                                choices_value = question.get('choices')
                                if isinstance(choices_value, str):
                                    answers = [answer.strip() for answer in choices_value.split('\n') if answer.strip()]
                                elif isinstance(choices_value, list):
                                    answers = [str(answer).strip() for answer in choices_value if str(answer).strip()]
                            
                            if answers:
                                question_data['correct_answers'] = answers
                            else:
                                # Skip questions without answers
                                continue
                        
                        # Add question to database
                        db.collection('questions').add(question_data)
                        added_count += 1
                    
                    # Update question count in quiz
                    quiz_ref.update({'question_count': Increment(added_count)})
                    
                    # Return JSON response
                    return jsonify({
                        'success': True, 
                        'message': f'Successfully imported {added_count} questions'
                    })
                    
            except Exception as e:
                return jsonify({
                    'success': False, 
                    'message': f'Error importing questions: {str(e)}'
                }), 400
        
        # Handle single question form submission (existing code)
        else:
            question_type = request.form['question_type']
            question_text = request.form['question_text']
            points = int(request.form.get('points', 1))
            
            question_data = {
                'quiz_id': quiz_id,
                'question_type': question_type,
                'question_text': question_text,
                'points': points,
                'created_at': datetime.now()
            }
            
            # Handle different question types
            if question_type == 'multiple_choice':
                options = [
                    request.form.get('option_a', ''),
                    request.form.get('option_b', ''),
                    request.form.get('option_c', ''),
                    request.form.get('option_d', '')
                ]
                correct_answer = request.form['correct_answer']
                question_data.update({
                    'options': options,
                    'correct_answer': correct_answer
                })
            
            elif question_type == 'true_false':
                correct_answer = request.form['tf_answer'] == 'true'
                question_data['correct_answer'] = correct_answer
            
            elif question_type in ['identification', 'enumeration']:
                correct_answers = [ans.strip() for ans in request.form['correct_answers'].split(',')]
                question_data['correct_answers'] = correct_answers
            
            try:
                db.collection('questions').add(question_data)
                
                # Update question count in quiz
                quiz_ref.update({'question_count': Increment(1)})
                
                flash('Question added successfully!')
                return redirect(url_for('manage_quiz', quiz_id=quiz_id))
            except Exception as e:
                flash(f'Error adding question: {e}')
    
    return render_template('add_question.html', quiz_id=quiz_id, quiz=quiz_data, username=session.get('username'), role=session.get('role'))

# Subject Edit and Delete Routes
@app.route('/subject/<subject_id>/edit', methods=['POST'])
def edit_subject(subject_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        # Verify ownership
        subject_ref = db.collection('subjects').document(subject_id)
        subject_doc = subject_ref.get()
        
        if not subject_doc.exists or subject_doc.to_dict()['teacher_id'] != session['user_id']:
            return jsonify({'success': False, 'message': 'Subject not found or access denied'}), 404
        
        # Get form data
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        
        if not name:
            return jsonify({'success': False, 'message': 'Subject name is required'}), 400
        
        # Update subject
        update_data = {
            'name': name,
            'description': description,
            'updated_at': datetime.now()
        }
        
        subject_ref.update(update_data)
        
        return jsonify({'success': True, 'message': 'Subject updated successfully'})
        
    except Exception as e:
        print(f"Error updating subject: {e}")
        return jsonify({'success': False, 'message': 'Error updating subject'}), 500

@app.route('/subject/<subject_id>/delete', methods=['POST'])
def delete_subject(subject_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        # Verify ownership
        subject_ref = db.collection('subjects').document(subject_id)
        subject_doc = subject_ref.get()
        
        if not subject_doc.exists or subject_doc.to_dict()['teacher_id'] != session['user_id']:
            return jsonify({'success': False, 'message': 'Subject not found or access denied'}), 404
        
        # Delete all topics associated with this subject
        topics_ref = db.collection('topics').where('subject_id', '==', subject_id)
        topic_docs = topics_ref.stream()
        for topic_doc in topic_docs:
            topic_doc.reference.delete()
        
        # Delete all quizzes associated with this subject
        quizzes_ref = db.collection('quizzes').where('subject_id', '==', subject_id)
        quiz_docs = quizzes_ref.stream()
        for quiz_doc in quiz_docs:
            quiz_id = quiz_doc.id
            # Delete questions in each quiz
            questions_ref = db.collection('questions').where('quiz_id', '==', quiz_id)
            question_docs = questions_ref.stream()
            for question_doc in question_docs:
                question_doc.reference.delete()
            # Delete the quiz
            quiz_doc.reference.delete()
        
        # Finally delete the subject
        subject_ref.delete()
        
        return jsonify({'success': True, 'message': 'Subject deleted successfully'})
        
    except Exception as e:
        print(f"Error deleting subject: {e}")
        return jsonify({'success': False, 'message': 'Error deleting subject'}), 500

@app.route('/quiz/<quiz_id>/edit', methods=['GET', 'POST'])
def edit_quiz(quiz_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        flash('Access denied. Teachers only.')
        return redirect(url_for('dashboard'))
    
    try:
        # Verify ownership
        quiz_ref = db.collection('quizzes').document(quiz_id)
        quiz_doc = quiz_ref.get()
        
        if not quiz_doc.exists or quiz_doc.to_dict()['teacher_id'] != session['user_id']:
            flash('Quiz not found or access denied.')
            return redirect(url_for('dashboard'))
        
        quiz_data = quiz_doc.to_dict()
        quiz_data['id'] = quiz_doc.id
        
        if request.method == 'POST':
            # Handle quiz update
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            time_limit = int(request.form.get('time_limit', 30))
            
            if not title:
                flash('Quiz title is required.')
                return render_template('edit_quiz.html', quiz=quiz_data)
            
            update_data = {
                'title': title,
                'description': description,
                'time_limit': time_limit,
                'updated_at': datetime.now()
            }
            
            quiz_ref.update(update_data)
            flash('Quiz updated successfully!')
            return redirect(url_for('manage_quiz', quiz_id=quiz_id), username=session.get('username'), role=session.get('role'))
        
        # Get teacher's subjects for dropdown
        subjects = []
        subjects_ref = db.collection('subjects').where('teacher_id', '==', session['user_id'])
        for doc in subjects_ref.stream():
            subject_data = doc.to_dict()
            subject_data['id'] = doc.id
            subjects.append(subject_data)
        
        return render_template('edit_quiz.html', quiz=quiz_data, subjects=subjects, username=session.get('username'), role=session.get('role'))
        
    except Exception as e:
        flash(f'Error accessing quiz: {e}')
        return redirect(url_for('dashboard'))

@app.route('/quiz/<quiz_id>/delete', methods=['POST'])
def delete_quiz(quiz_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        # Verify ownership
        quiz_ref = db.collection('quizzes').document(quiz_id)
        quiz_doc = quiz_ref.get()
        
        if not quiz_doc.exists or quiz_doc.to_dict()['teacher_id'] != session['user_id']:
            return jsonify({'success': False, 'message': 'Quiz not found or access denied'}), 404
        
        # Delete all questions associated with this quiz
        questions_ref = db.collection('questions').where('quiz_id', '==', quiz_id)
        question_docs = questions_ref.stream()
        for question_doc in question_docs:
            question_doc.reference.delete()
        
        # Delete the quiz
        quiz_ref.delete()
        
        return jsonify({'success': True, 'message': 'Quiz deleted successfully'})
        
    except Exception as e:
        print(f"Error deleting quiz: {e}")
        return jsonify({'success': False, 'message': 'Error deleting quiz'}), 500

@app.route('/quiz/<quiz_id>/preview')
def preview_quiz(quiz_id):
    if 'user_id' not in session:
        flash('Please log in to preview quizzes.')
        return redirect(url_for('login'))
    
    try:
        # Get quiz details
        quiz_ref = db.collection('quizzes').document(quiz_id)
        quiz_doc = quiz_ref.get()
        
        if not quiz_doc.exists:
            flash('Quiz not found.')
            return redirect(url_for('dashboard'))
        
        quiz_data = quiz_doc.to_dict()
        quiz_data['id'] = quiz_doc.id
        
        # For teachers, allow preview of their own quizzes regardless of publish status
        # For students, only allow preview of published quizzes
        if session.get('role') == 'student' and not quiz_data.get('is_published', False):
            flash('This quiz is not available.')
            return redirect(url_for('dashboard'))
        
        # Get questions for this quiz
        questions = []
        questions_ref = db.collection('questions').where('quiz_id', '==', quiz_id).order_by('created_at')
        for doc in questions_ref.stream():
            question_data = doc.to_dict()
            question_data['id'] = doc.id
            questions.append(question_data)
        
        return render_template('quiz_preview.html', quiz=quiz_data, questions=questions)
        
    except Exception as e:
        flash(f'Error loading quiz preview: {e}')
        return redirect(url_for('dashboard'))
    
@app.route('/quiz/<quiz_id>/question/<question_id>/edit', methods=['GET', 'POST'])
def edit_question(quiz_id, question_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        flash('Access denied. Teachers only.')
        return redirect(url_for('dashboard'))
    
    try:
        # Verify quiz ownership
        quiz_ref = db.collection('quizzes').document(quiz_id)
        quiz_doc = quiz_ref.get()
        
        if not quiz_doc.exists or quiz_doc.to_dict()['teacher_id'] != session['user_id']:
            flash('Quiz not found or access denied.')
            return redirect(url_for('dashboard'))
        
        quiz_data = quiz_doc.to_dict()
        quiz_data['id'] = quiz_doc.id
        
        # Get question data
        question_ref = db.collection('questions').document(question_id)
        question_doc = question_ref.get()
        
        if not question_doc.exists:
            flash('Question not found.')
            return redirect(url_for('manage_quiz', quiz_id=quiz_id))
        
        question_data = question_doc.to_dict()
        question_data['id'] = question_doc.id
        
        # Verify question belongs to this quiz
        if question_data['quiz_id'] != quiz_id:
            flash('Question does not belong to this quiz.')
            return redirect(url_for('manage_quiz', quiz_id=quiz_id))
        
        if request.method == 'POST':
            question_type = request.form['question_type']
            question_text = request.form['question_text']
            points = int(request.form.get('points', 1))
            
            update_data = {
                'question_type': question_type,
                'question_text': question_text,
                'points': points,
                'updated_at': datetime.now()
            }
            
            # Handle different question types
            if question_type == 'multiple_choice':
                options = [
                    request.form.get('option_a', ''),
                    request.form.get('option_b', ''),
                    request.form.get('option_c', ''),
                    request.form.get('option_d', '')
                ]
                correct_answer = request.form['correct_answer']
                update_data.update({
                    'options': options,
                    'correct_answer': correct_answer
                })
            
            elif question_type == 'true_false':
                correct_answer = request.form['tf_answer'] == 'true'
                update_data['correct_answer'] = correct_answer
            
            elif question_type in ['identification', 'enumeration']:
                correct_answers = [ans.strip() for ans in request.form['correct_answers'].split(',')]
                update_data['correct_answers'] = correct_answers
            
            try:
                question_ref.update(update_data)
                flash('Question updated successfully!')
                return redirect(url_for('manage_quiz', quiz_id=quiz_id))
            except Exception as e:
                flash(f'Error updating question: {e}')
        
        return render_template('edit_question.html', quiz=quiz_data, question=question_data, quiz_id=quiz_id)
        
    except Exception as e:
        flash(f'Error accessing question: {e}')
        return redirect(url_for('manage_quiz', quiz_id=quiz_id))

@app.route('/quiz/<quiz_id>/question/<question_id>/delete', methods=['POST'])
def delete_question(quiz_id, question_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        # Verify quiz ownership
        quiz_ref = db.collection('quizzes').document(quiz_id)
        quiz_doc = quiz_ref.get()
        
        if not quiz_doc.exists or quiz_doc.to_dict()['teacher_id'] != session['user_id']:
            return jsonify({'success': False, 'message': 'Quiz not found or access denied'}), 404
        
        # Get and verify question
        question_ref = db.collection('questions').document(question_id)
        question_doc = question_ref.get()
        
        if not question_doc.exists:
            return jsonify({'success': False, 'message': 'Question not found'}), 404
        
        question_data = question_doc.to_dict()
        
        # Verify question belongs to this quiz
        if question_data['quiz_id'] != quiz_id:
            return jsonify({'success': False, 'message': 'Question does not belong to this quiz'}), 400
        
        # Delete the question
        question_ref.delete()
        
        # Update question count in quiz
        quiz_ref.update({'question_count': Increment(-1)})
        
        return jsonify({'success': True, 'message': 'Question deleted successfully'})
        
    except Exception as e:
        print(f"Error deleting question: {e}")
        return jsonify({'success': False, 'message': 'Error deleting question'}), 500
    
# Add these routes to your Flask app

# @app.route('/quiz/<quiz_id>/take')
# def take_quiz(quiz_id):
#     if 'user_id' not in session:
#         flash('Please log in to take quizzes.')
#         return redirect(url_for('login'))
    
#     try:
#         # Get quiz details
#         quiz_ref = db.collection('quizzes').document(quiz_id)
#         quiz_doc = quiz_ref.get()
        
#         if not quiz_doc.exists:
#             flash('Quiz not found.')
#             return redirect(url_for('dashboard'))
        
#         quiz_data = quiz_doc.to_dict()
#         quiz_data['id'] = quiz_doc.id
        
#         # Check if quiz is published
#         if not quiz_data.get('is_published', False):
#             flash('This quiz is not available.')
#             return redirect(url_for('dashboard'))
        
#         # Get questions for this quiz
#         questions = []
#         questions_ref = db.collection('questions').where('quiz_id', '==', quiz_id).order_by('created_at')
#         for doc in questions_ref.stream():
#             question_data = doc.to_dict()
#             question_data['id'] = doc.id
#             questions.append(question_data)
        
#         if not questions:
#             flash('This quiz has no questions yet.')
#             return redirect(url_for('dashboard'))
        
#         return render_template('take_quiz.html', quiz=quiz_data, questions=questions)
        
#     except Exception as e:
#         flash(f'Error loading quiz: {e}')
#         return redirect(url_for('dashboard'))
@app.route('/quiz/<quiz_id>/take')
def take_quiz(quiz_id):
    if 'user_id' not in session:
        flash('Please log in to take quizzes.')
        return redirect(url_for('login'))
    
    try:
        # Get quiz details
        quiz_ref = db.collection('quizzes').document(quiz_id)
        quiz_doc = quiz_ref.get()
        
        if not quiz_doc.exists:
            flash('Quiz not found.')
            return redirect(url_for('dashboard'))
        
        quiz_data = quiz_doc.to_dict()
        quiz_data['id'] = quiz_doc.id
        
        # Check if quiz is published
        if not quiz_data.get('is_published', False):
            flash('This quiz is not available.')
            return redirect(url_for('dashboard'))
        
        # Check enrollment for students
        if session.get('role') == 'student':
            is_enrolled = check_enrollment(session['user_id'], quiz_data['subject_id'])
            if not is_enrolled:
                flash('You must be enrolled in this subject to take quizzes.')
                return redirect(url_for('view_subject', subject_id=quiz_data['subject_id']))
        
        # Get questions for this quiz
        questions = []
        questions_ref = db.collection('questions').where('quiz_id', '==', quiz_id).order_by('created_at')
        for doc in questions_ref.stream():
            question_data = doc.to_dict()
            question_data['id'] = doc.id
            questions.append(question_data)
        
        if not questions:
            flash('This quiz has no questions yet.')
            return redirect(url_for('dashboard'))
        
        # Check if user has already taken this quiz (if attempts are limited)
        if quiz_data.get('max_attempts', 0) > 0:
            attempts_count = db.collection('quiz_attempts').where('quiz_id', '==', quiz_id).where('user_id', '==', session['user_id']).stream()
            current_attempts = len(list(attempts_count))
            if current_attempts >= quiz_data['max_attempts']:
                flash(f'You have already used all {quiz_data["max_attempts"]} attempts for this quiz.')
                return redirect(url_for('quiz_results', quiz_id=quiz_id))
        
        # Add subject name if not present
        if 'subject_name' not in quiz_data and quiz_data.get('subject_id'):
            subject_doc = db.collection('subjects').document(quiz_data['subject_id']).get()
            if subject_doc.exists:
                quiz_data['subject_name'] = subject_doc.to_dict().get('name', 'Unknown Subject')
        
        return render_template('take_quiz.html', 
                             quiz=quiz_data, 
                             questions=questions,
                             username=session.get('username'),
                             role=session.get('role'))

    except Exception as e:
        flash(f'Error loading quiz: {e}')
        return redirect(url_for('dashboard'))


@app.route('/quiz/<quiz_id>/submit', methods=['POST'])
def submit_quiz(quiz_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in'}), 401
    
    try:
        # Get quiz details
        quiz_ref = db.collection('quizzes').document(quiz_id)
        quiz_doc = quiz_ref.get()
        
        if not quiz_doc.exists:
            return jsonify({'success': False, 'message': 'Quiz not found'}), 404
        
        quiz_data = quiz_doc.to_dict()
        
        # Get submitted answers
        submitted_answers = request.json.get('answers', {})
        
        # Get questions and calculate score
        questions_ref = db.collection('questions').where('quiz_id', '==', quiz_id)
        questions = list(questions_ref.stream())
        
        total_points = 0
        earned_points = 0
        results = {}
        
        for question_doc in questions:
            question_data = question_doc.to_dict()
            question_id = question_doc.id
            total_points += question_data.get('points', 1)
            
            user_answer = submitted_answers.get(question_id)
            is_correct = False
            
            # Check answer based on question type
            if question_data['question_type'] == 'multiple_choice':
                is_correct = user_answer == question_data.get('correct_answer')
            
            elif question_data['question_type'] == 'true_false':
                user_bool = user_answer == 'true' if isinstance(user_answer, str) else user_answer
                is_correct = user_bool == question_data.get('correct_answer')
            
            elif question_data['question_type'] in ['identification', 'enumeration']:
                correct_answers = question_data.get('correct_answers', [])
                if isinstance(user_answer, str):
                    # For identification, check if user answer matches any correct answer (case-insensitive)
                    user_answer_clean = user_answer.strip().lower()
                    is_correct = any(ans.strip().lower() == user_answer_clean for ans in correct_answers)
                elif isinstance(user_answer, list):
                    # For enumeration, check if all user answers are in correct answers
                    user_answers_clean = [ans.strip().lower() for ans in user_answer]
                    correct_answers_clean = [ans.strip().lower() for ans in correct_answers]
                    is_correct = all(ans in correct_answers_clean for ans in user_answers_clean)
            
            if is_correct:
                earned_points += question_data.get('points', 1)
            
            results[question_id] = {
                'user_answer': user_answer,
                'correct_answer': question_data.get('correct_answer') or question_data.get('correct_answers'),
                'is_correct': is_correct,
                'points': question_data.get('points', 1)
            }
        
        # Calculate percentage
        percentage = (earned_points / total_points * 100) if total_points > 0 else 0
        
        # Save quiz attempt to database
        attempt_data = {
            'quiz_id': quiz_id,
            'quiz_title': quiz_data.get('title'),
            'user_id': session['user_id'],
            'username': session['username'],
            'submitted_answers': submitted_answers,
            'results': results,
            'total_points': total_points,
            'earned_points': earned_points,
            'percentage': percentage,
            'submitted_at': datetime.now()
        }
        
        attempt_ref = db.collection('quiz_attempts').add(attempt_data)
        attempt_id = attempt_ref[1].id
        
        return jsonify({
            'success': True,
            'attempt_id': attempt_id,
            'score': earned_points,
            'total': total_points,
            'percentage': round(percentage, 2)
        })
        
    except Exception as e:
        print(f"Error submitting quiz: {e}")
        return jsonify({'success': False, 'message': 'Error submitting quiz'}), 500

# @app.route('/quiz/<quiz_id>/results')
# def quiz_results(quiz_id):
#     if 'user_id' not in session:
#         flash('Please log in to view results.')
#         return redirect(url_for('login'))
    
#     try:
#         # Get quiz details
#         quiz_ref = db.collection('quizzes').document(quiz_id)
#         quiz_doc = quiz_ref.get()
        
#         if not quiz_doc.exists:
#             flash('Quiz not found.')
#             return redirect(url_for('dashboard'))
        
#         quiz_data = quiz_doc.to_dict()
#         quiz_data['id'] = quiz_doc.id
        
#         # Get user's attempts for this quiz
#         attempts = []
#         attempts_ref = db.collection('quiz_attempts').where('quiz_id', '==', quiz_id).where('user_id', '==', session['user_id']).order_by('submitted_at', direction=firestore.Query.DESCENDING)
        
#         for doc in attempts_ref.stream():
#             attempt_data = doc.to_dict()
#             attempt_data['id'] = doc.id
#             attempts.append(attempt_data)
        
#         return render_template('quiz_results.html', quiz=quiz_data, attempts=attempts)
        
#     except Exception as e:
#         flash(f'Error loading results: {e}')
#         return redirect(url_for('dashboard'))

# Add this debugging route to test if your Flask app is working
@app.route('/debug/routes')
def debug_routes():
    """Debug route to see all registered routes"""
    import urllib
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        line = urllib.parse.unquote("{:50s} {:20s} {}".format(rule.endpoint, methods, rule))
        output.append(line)
    
    return '<pre>' + '\n'.join(sorted(output)) + '</pre>'

# Make sure your quiz_results route is properly defined with error handling
@app.route('/quiz/<quiz_id>/results')
def quiz_results(quiz_id):
    print(f"DEBUG: Accessing quiz results for quiz_id: {quiz_id}")
    
    if 'user_id' not in session:
        flash('Please log in to view results.')
        return redirect(url_for('login'))
    
    try:
        # Get quiz details
        quiz_ref = db.collection('quizzes').document(quiz_id)
        quiz_doc = quiz_ref.get()
        
        print(f"DEBUG: Quiz document exists: {quiz_doc.exists}")
        
        if not quiz_doc.exists:
            flash('Quiz not found.')
            return redirect(url_for('dashboard'))
        
        quiz_data = quiz_doc.to_dict()
        quiz_data['id'] = quiz_doc.id
        
        print(f"DEBUG: Quiz data loaded: {quiz_data.get('title', 'No title')}")
        
        # For teachers, allow viewing results of their own quizzes
        # For students, only allow viewing results of published quizzes they're enrolled in
        if session.get('role') == 'student':
            if not quiz_data.get('is_published', False):
                flash('This quiz is not available.')
                return redirect(url_for('dashboard'))
            
            # Check enrollment for students
            is_enrolled = check_enrollment(session['user_id'], quiz_data['subject_id'])
            if not is_enrolled:
                flash('You must be enrolled in this subject to view quiz results.')
                return redirect(url_for('view_subject', subject_id=quiz_data['subject_id']))
        
        elif session.get('role') == 'teacher':
            # Teachers can only view results for their own quizzes
            if quiz_data.get('teacher_id') != session['user_id']:
                flash('You can only view results for your own quizzes.')
                return redirect(url_for('dashboard'))
        
        # Get user's attempts for this quiz
        attempts = []
        attempts_ref = db.collection('quiz_attempts').where('quiz_id', '==', quiz_id).where('user_id', '==', session['user_id']).order_by('submitted_at', direction=firestore.Query.DESCENDING)
        
        for doc in attempts_ref.stream():
            attempt_data = doc.to_dict()
            attempt_data['id'] = doc.id
            attempts.append(attempt_data)
        
        print(f"DEBUG: Found {len(attempts)} attempts")
        
        # Add question count to quiz data if not present
        if 'question_count' not in quiz_data:
            questions_count = len(list(db.collection('questions').where('quiz_id', '==', quiz_id).stream()))
            quiz_data['question_count'] = questions_count
        
        # Get subject and teacher names for display
        if 'subject_name' not in quiz_data and quiz_data.get('subject_id'):
            subject_doc = db.collection('subjects').document(quiz_data['subject_id']).get()
            if subject_doc.exists:
                quiz_data['subject_name'] = subject_doc.to_dict().get('name', 'Unknown Subject')
        
        if 'teacher_name' not in quiz_data and quiz_data.get('teacher_id'):
            teacher_doc = db.collection('users').document(quiz_data['teacher_id']).get()
            if teacher_doc.exists:
                teacher_data = teacher_doc.to_dict()
                quiz_data['teacher_name'] = f"{teacher_data.get('first_name', '')} {teacher_data.get('last_name', '')}".strip()
        
        return render_template('quiz_results.html', 
                             quiz=quiz_data, 
                             attempts=attempts,
                             username=session.get('username'),
                             role=session.get('role'))
        
    except Exception as e:
        print(f"ERROR in quiz_results: {e}")
        flash(f'Error loading results: {e}')
        return redirect(url_for('dashboard'))
    
# @app.route('/quiz-attempt/<attempt_id>')
# def view_attempt(attempt_id):
#     if 'user_id' not in session:
#         flash('Please log in to view attempt details.')
#         return redirect(url_for('login'))
    
#     try:
#         # Get attempt details
#         attempt_ref = db.collection('quiz_attempts').document(attempt_id)
#         attempt_doc = attempt_ref.get()
        
#         if not attempt_doc.exists:
#             flash('Attempt not found.')
#             return redirect(url_for('dashboard'))
        
#         attempt_data = attempt_doc.to_dict()
        
#         # Verify user owns this attempt
#         if attempt_data['user_id'] != session['user_id']:
#             flash('Access denied.')
#             return redirect(url_for('dashboard'))
        
#         # Get quiz details
#         quiz_ref = db.collection('quizzes').document(attempt_data['quiz_id'])
#         quiz_doc = quiz_ref.get()
#         quiz_data = quiz_doc.to_dict() if quiz_doc.exists else {}
        
#         # Get questions with details
#         questions = []
#         questions_ref = db.collection('questions').where('quiz_id', '==', attempt_data['quiz_id']).order_by('created_at')
#         for doc in questions_ref.stream():
#             question_data = doc.to_dict()
#             question_data['id'] = doc.id
#             questions.append(question_data)
        
#         return render_template('attempt_detail.html', 
#                              attempt=attempt_data, 
#                              quiz=quiz_data, 
#                              questions=questions)
        
#     except Exception as e:
#         flash(f'Error loading attempt: {e}')
#         return redirect(url_for('dashboard'))

@app.route('/quiz-attempt/<attempt_id>')
def view_attempt(attempt_id):
    if 'user_id' not in session:
        flash('Please log in to view attempt details.')
        return redirect(url_for('login'))
    
    try:
        # Get attempt details
        attempt_ref = db.collection('quiz_attempts').document(attempt_id)
        attempt_doc = attempt_ref.get()
        
        if not attempt_doc.exists:
            flash('Attempt not found.')
            return redirect(url_for('dashboard'))
        
        attempt_data = attempt_doc.to_dict()
        attempt_data['id'] = attempt_doc.id
        
        # Verify user owns this attempt
        if attempt_data['user_id'] != session['user_id']:
            flash('Access denied.')
            return redirect(url_for('dashboard'))
        
        # Get quiz details
        quiz_data = None
        try:
            quiz_ref = db.collection('quizzes').document(attempt_data['quiz_id'])
            quiz_doc = quiz_ref.get()
            if quiz_doc.exists:
                quiz_data = quiz_doc.to_dict()
                quiz_data['id'] = quiz_doc.id
                
                # Add subject name if available
                if 'subject_name' not in quiz_data and quiz_data.get('subject_id'):
                    subject_doc = db.collection('subjects').document(quiz_data['subject_id']).get()
                    if subject_doc.exists:
                        quiz_data['subject_name'] = subject_doc.to_dict().get('name', 'Unknown Subject')
                        
        except Exception as e:
            print(f"Error loading quiz data: {e}")
        
        # Get questions with details
        questions = []
        questions_ref = db.collection('questions').where('quiz_id', '==', attempt_data['quiz_id']).order_by('created_at')
        for doc in questions_ref.stream():
            question_data = doc.to_dict()
            question_data['id'] = doc.id
            questions.append(question_data)
        
        return render_template('attempt_detail.html', 
                             attempt=attempt_data, 
                             quiz=quiz_data,
                             questions=questions,
                             username=session.get('username'),
                             role=session.get('role'))

    except Exception as e:
        flash(f'Error loading attempt: {e}')
        return redirect(url_for('dashboard'))

# @app.route('/compare-attempts/<attempt1_id>/<attempt2_id>')
# def compare_attempts(attempt1_id, attempt2_id):
#     if 'user_id' not in session:
#         flash('Please log in to compare attempts.')
#         return redirect(url_for('login'))
    
#     try:
#         # Get both attempts
#         attempt1_ref = db.collection('quiz_attempts').document(attempt1_id)
#         attempt1_doc = attempt1_ref.get()
        
#         attempt2_ref = db.collection('quiz_attempts').document(attempt2_id)
#         attempt2_doc = attempt2_ref.get()
        
#         if not attempt1_doc.exists or not attempt2_doc.exists:
#             flash('One or both attempts not found.')
#             return redirect(url_for('dashboard'))
        
#         attempt1_data = attempt1_doc.to_dict()
#         attempt1_data['id'] = attempt1_doc.id
        
#         attempt2_data = attempt2_doc.to_dict()
#         attempt2_data['id'] = attempt2_doc.id
        
#         # Verify user owns both attempts
#         if (attempt1_data['user_id'] != session['user_id'] or 
#             attempt2_data['user_id'] != session['user_id']):
#             flash('Access denied.')
#             return redirect(url_for('dashboard'))
        
#         # Get quiz details
#         quiz_ref = db.collection('quizzes').document(attempt1_data['quiz_id'])
#         quiz_doc = quiz_ref.get()
#         quiz_data = quiz_doc.to_dict() if quiz_doc.exists else None
        
#         # Get questions
#         questions = []
#         questions_ref = db.collection('questions').where('quiz_id', '==', attempt1_data['quiz_id']).order_by('created_at')
#         for doc in questions_ref.stream():
#             question_data = doc.to_dict()
#             question_data['id'] = doc.id
#             questions.append(question_data)
        
#         return render_template('compare_attempts.html', 
#                              attempt1=attempt1_data, 
#                              attempt2=attempt2_data,
#                              quiz=quiz_data,
#                              questions=questions,
#                              username=session.get('username'),
#                              role=session.get('role'))
        
#     except Exception as e:
#         flash(f'Error comparing attempts: {e}')
#         return redirect(url_for('dashboard'))

@app.route('/subject/<subject_id>/enroll', methods=['POST'])
def enroll_subject(subject_id):
    if 'user_id' not in session or session.get('role') != 'student':
        return jsonify({'success': False, 'message': 'Students only'}), 403
    
    try:
        # Check if subject exists
        subject_ref = db.collection('subjects').document(subject_id)
        subject_doc = subject_ref.get()
        
        if not subject_doc.exists:
            return jsonify({'success': False, 'message': 'Subject not found'}), 404
        
        subject_data = subject_doc.to_dict()
        
        # Check if already enrolled (ACTIVE enrollments only)
        enrollments_ref = db.collection('enrollments')
        existing_enrollment = enrollments_ref.where('student_id', '==', session['user_id']).where('subject_id', '==', subject_id).where('status', '==', 'active').get()
        
        if len(existing_enrollment) > 0:  # Check length instead of truthiness
            return jsonify({'success': False, 'message': 'Already enrolled in this subject'}), 400
        
        # Create enrollment
        enrollment_data = {
            'student_id': session['user_id'],
            'student_name': session['username'],
            'subject_id': subject_id,
            'subject_name': subject_data['name'],
            'teacher_id': subject_data['teacher_id'],
            'teacher_name': subject_data['teacher_name'],
            'enrolled_at': datetime.now(),
            'status': 'active'
        }
        
        enrollments_ref.add(enrollment_data)
        
        return jsonify({'success': True, 'message': 'Successfully enrolled in subject'})
        
    except Exception as e:
        print(f"Error enrolling in subject: {e}")
        return jsonify({'success': False, 'message': 'Error enrolling in subject'}), 500

@app.route('/subject/<subject_id>/unenroll', methods=['POST'])
def unenroll_subject(subject_id):
    if 'user_id' not in session or session.get('role') != 'student':
        return jsonify({'success': False, 'message': 'Students only'}), 403
    
    try:
        # Find ACTIVE enrollment only
        enrollments_ref = db.collection('enrollments')
        enrollment_docs = enrollments_ref.where('student_id', '==', session['user_id']).where('subject_id', '==', subject_id).where('status', '==', 'active').get()
        
        if len(enrollment_docs) == 0:  # Check length instead of truthiness
            return jsonify({'success': False, 'message': 'Not enrolled in this subject'}), 400
        
        # Update enrollment status to 'inactive' instead of deleting (for activity tracking)
        for doc in enrollment_docs:
            doc.reference.update({
                'status': 'inactive',
                'unenrolled_at': datetime.now()
            })
        
        return jsonify({'success': True, 'message': 'Successfully unenrolled from subject'})
        
    except Exception as e:
        print(f"Error unenrolling from subject: {e}")
        return jsonify({'success': False, 'message': 'Error unenrolling from subject'}), 500

# Helper function to check enrollment (this one is correct)
def check_enrollment(student_id, subject_id):
    """Check if a student is enrolled in a subject"""
    try:
        enrollments_ref = db.collection('enrollments')
        enrollment_docs = enrollments_ref.where('student_id', '==', student_id).where('subject_id', '==', subject_id).where('status', '==', 'active').get()
        return len(enrollment_docs) > 0
    except:
        return False

@app.route('/api/generate-flashcards', methods=['POST'])
def generate_flashcards():
    data = request.get_json()
    content = data.get('content')
    count = data.get('count', 10)
    difficulty = data.get('difficulty', 'medium')
    
    # Call your AI service here
    flashcards = call_ai_service(content, count, difficulty)
    
    return jsonify({
        'success': True,
        'flashcards': flashcards
    })

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.')
    return redirect(url_for('home'))

# @app.route('/forgot-password', methods=['GET', 'POST'])
# def forgot_password():
#     if request.method == 'POST':
#         email = request.form.get('email', '').strip()
        
#         if not email:
#             flash('Please enter your email address.')
#             return render_template('forgot_password.html')
        
#         try:
#             # Check if user exists
#             users_ref = db.collection('users')
#             user_docs = users_ref.where('email', '==', email).get()
            
#             if not user_docs:
#                 # Don't reveal if email exists or not for security
#                 flash('If an account with that email exists, we\'ve sent you a password reset link.')
#                 return redirect(url_for('login'))
            
#             user_doc = user_docs[0]
#             user_data = user_doc.to_dict()
#             user_id = user_doc.id
            
#             # Generate reset token
#             reset_token = secrets.token_urlsafe(32)
#             token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
            
#             # Set token expiration (1 hour from now)
#             expires_at = datetime.now() + timedelta(hours=1)
            
#             # Store reset token in database
#             reset_data = {
#                 'user_id': user_id,
#                 'token_hash': token_hash,
#                 'email': email,
#                 'expires_at': expires_at,
#                 'used': False,
#                 'created_at': datetime.now()
#             }
            
#             db.collection('password_resets').add(reset_data)
            
#             # Send reset email
#             reset_url = url_for('reset_password', token=reset_token, _external=True)
            
#             msg = Message(
#                 'Reset Your Quizera Password',
#                 recipients=[email],
#                 html=f'''
#                 <html>
#                 <body>
#                     <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
#                         <h2 style="color: #2563eb;">Reset Your Password</h2>
#                         <p>Hello {user_data.get('username', 'there')},</p>
#                         <p>You requested to reset your password for your Quizera account. Click the button below to reset it:</p>
#                         <div style="text-align: center; margin: 30px 0;">
#                             <a href="{reset_url}" 
#                                style="background-color: #2563eb; color: white; padding: 12px 24px; 
#                                       text-decoration: none; border-radius: 5px; display: inline-block;">
#                                 Reset Password
#                             </a>
#                         </div>
#                         <p>Or copy and paste this link into your browser:</p>
#                         <p><a href="{reset_url}">{reset_url}</a></p>
#                         <p><strong>This link will expire in 1 hour.</strong></p>
#                         <p>If you didn't request this password reset, please ignore this email.</p>
#                         <hr style="margin: 30px 0; border: 1px solid #e5e5e5;">
#                         <p style="color: #666; font-size: 12px;">
#                             This is an automated message from Quizera. Please do not reply to this email.
#                         </p>
#                     </div>
#                 </body>
#                 </html>
#                 '''
#             )
            
#             mail.send(msg)
#             flash('If an account with that email exists, we\'ve sent you a password reset link.')
#             return redirect(url_for('login'))
            
#         except Exception as e:
#             print(f"Error sending password reset: {e}")
#             flash('An error occurred. Please try again later.')
    
#     return render_template('forgot_password.html')

# @app.route('/reset-password/<token>', methods=['GET', 'POST'])
# def reset_password(token):
#     if request.method == 'GET':
#         # Verify token exists and is valid
#         token_hash = hashlib.sha256(token.encode()).hexdigest()
        
#         try:
#             resets_ref = db.collection('password_resets')
#             reset_docs = resets_ref.where('token_hash', '==', token_hash).where('used', '==', False).get()
            
#             if not reset_docs:
#                 flash('Invalid or expired reset link.')
#                 return redirect(url_for('forgot_password'))
            
#             reset_doc = reset_docs[0]
#             reset_data = reset_doc.to_dict()
            
#             # Check if token is expired
#             if datetime.now() > reset_data['expires_at']:
#                 flash('This reset link has expired. Please request a new one.')
#                 return redirect(url_for('forgot_password'))
            
#             return render_template('reset_password.html', token=token, email=reset_data.get('email'))
            
#         except Exception as e:
#             print(f"Error validating reset token: {e}")
#             flash('An error occurred. Please try again.')
#             return redirect(url_for('forgot_password'))
    
#     elif request.method == 'POST':
#         new_password = request.form.get('new_password', '').strip()
#         confirm_password = request.form.get('confirm_password', '').strip()
        
#         if not new_password or not confirm_password:
#             flash('Please fill in all fields.')
#             return render_template('reset_password.html', token=token)
        
#         if len(new_password) < 6:
#             flash('Password must be at least 6 characters long.')
#             return render_template('reset_password.html', token=token)
        
#         if new_password != confirm_password:
#             flash('Passwords do not match.')
#             return render_template('reset_password.html', token=token)
        
#         try:
#             token_hash = hashlib.sha256(token.encode()).hexdigest()
            
#             # Find and validate reset token
#             resets_ref = db.collection('password_resets')
#             reset_docs = resets_ref.where('token_hash', '==', token_hash).where('used', '==', False).get()
            
#             if not reset_docs:
#                 flash('Invalid or expired reset link.')
#                 return redirect(url_for('forgot_password'))
            
#             reset_doc = reset_docs[0]
#             reset_data = reset_doc.to_dict()
            
#             # Check if token is expired
#             if datetime.now() > reset_data['expires_at']:
#                 flash('This reset link has expired. Please request a new one.')
#                 return redirect(url_for('forgot_password'))
            
#             # Update user password
#             user_ref = db.collection('users').document(reset_data['user_id'])
#             hashed_password = generate_password_hash(new_password)
            
#             user_ref.update({
#                 'password': hashed_password,
#                 'password_updated_at': datetime.now()
#             })
            
#             # Mark reset token as used
#             reset_doc.reference.update({
#                 'used': True,
#                 'used_at': datetime.now()
#             })
            
#             flash('Your password has been updated successfully! You can now log in.')
#             return redirect(url_for('login'))
            
#         except Exception as e:
#             print(f"Error resetting password: {e}")
#             flash('An error occurred while resetting your password. Please try again.')
#             return render_template('reset_password.html', token=token)

# Optional: Cleanup expired reset tokens (run this periodically)
@app.route('/admin/cleanup-expired-tokens', methods=['POST'])
def cleanup_expired_tokens():
    """Admin route to clean up expired password reset tokens"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        # Delete expired tokens
        resets_ref = db.collection('password_resets')
        expired_docs = resets_ref.where('expires_at', '<', datetime.now()).get()
        
        deleted_count = 0
        for doc in expired_docs:
            doc.reference.delete()
            deleted_count += 1
        
        return jsonify({
            'success': True, 
            'message': f'Cleaned up {deleted_count} expired tokens'
        })
        
    except Exception as e:
        return jsonify({
            'success': False, 
            'message': f'Error cleaning up tokens: {e}'
        }), 500



@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if not email:
            flash('Please enter your email address.')
            return render_template('forgot_password.html')
        
        try:
            # Check if user exists
            users_ref = db.collection('users')
            user_docs = list(users_ref.where('email', '==', email).get())
            
            if not user_docs:
                # Don't reveal if email exists or not for security
                flash('If an account with that email exists, we\'ve sent you a password reset link.')
                return redirect(url_for('login'))
            
            user_doc = user_docs[0]
            user_data = user_doc.to_dict()
            user_id = user_doc.id
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
            
            # Set token expiration (1 hour from now) - using UTC to avoid timezone issues
            from datetime import datetime, timedelta, timezone
            current_time = datetime.now(timezone.utc)
            expires_at = current_time + timedelta(hours=1)
            
            print(f"DEBUG: Creating reset token")
            print(f"DEBUG: Current time (UTC): {current_time}")
            print(f"DEBUG: Expires at (UTC): {expires_at}")
            print(f"DEBUG: Token: {reset_token}")
            print(f"DEBUG: Token hash: {token_hash}")
            
            # Store reset token in database
            reset_data = {
                'user_id': user_id,
                'token_hash': token_hash,
                'email': email,
                'expires_at': expires_at,
                'used': False,
                'created_at': current_time
            }
            
            reset_ref = db.collection('password_resets').add(reset_data)
            print(f"DEBUG: Reset token stored with ID: {reset_ref[1].id}")
            
            # Send reset email
            reset_url = url_for('reset_password', token=reset_token, _external=True)
            print(f"DEBUG: Reset URL: {reset_url}")
            
            msg = Message(
                'Reset Your Quizera Password',
                recipients=[email],
                html=f'''
                <html>
                <body>
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #2563eb;">Reset Your Password</h2>
                        <p>Hello {user_data.get('username', 'there')},</p>
                        <p>You requested to reset your password for your Quizera account. Click the button below to reset it:</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{reset_url}" 
                               style="background-color: #2563eb; color: white; padding: 12px 24px; 
                                      text-decoration: none; border-radius: 5px; display: inline-block;">
                                Reset Password
                            </a>
                        </div>
                        <p>Or copy and paste this link into your browser:</p>
                        <p><a href="{reset_url}">{reset_url}</a></p>
                        <p><strong>This link will expire in 1 hour.</strong></p>
                        <p>If you didn't request this password reset, please ignore this email.</p>
                        <hr style="margin: 30px 0; border: 1px solid #e5e5e5;">
                        <p style="color: #666; font-size: 12px;">
                            This is an automated message from Quizera. Please do not reply to this email.
                        </p>
                    </div>
                </body>
                </html>
                '''
            )
            
            mail.send(msg)
            print("DEBUG: Email sent successfully")
            flash('If an account with that email exists, we\'ve sent you a password reset link.')
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"ERROR in forgot_password: {e}")
            import traceback
            traceback.print_exc()
            flash('An error occurred. Please try again later.')
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    print(f"DEBUG: Reset password accessed with token: {token}")
    print(f"DEBUG: Request method: {request.method}")
    
    if request.method == 'GET':
        # Verify token exists and is valid
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        print(f"DEBUG: Token hash: {token_hash}")
        
        try:
            resets_ref = db.collection('password_resets')
            reset_docs = list(resets_ref.where('token_hash', '==', token_hash).where('used', '==', False).get())
            
            print(f"DEBUG: Found {len(reset_docs)} matching reset docs")
            
            if not reset_docs:
                print("DEBUG: No matching reset docs found")
                flash('Invalid or expired reset link.')
                return redirect(url_for('forgot_password'))
            
            reset_doc = reset_docs[0]
            reset_data = reset_doc.to_dict()
            
            print(f"DEBUG: Reset data: {reset_data}")
            
            # Get current time in UTC and ensure comparison consistency
            from datetime import datetime, timezone
            current_time = datetime.now(timezone.utc)
            print(f"DEBUG: Current time (UTC): {current_time}")
            
            # Handle the expires_at field - it might be stored differently
            expires_at = reset_data['expires_at']
            print(f"DEBUG: Expires at (raw): {expires_at}")
            print(f"DEBUG: Expires at type: {type(expires_at)}")
            
            # Convert expires_at to UTC datetime if needed
            if hasattr(expires_at, 'timestamp'):
                # If it's a Firestore timestamp, convert to datetime
                expires_at_dt = expires_at.replace(tzinfo=timezone.utc)
            elif isinstance(expires_at, datetime):
                # If it's already a datetime, ensure it has timezone info
                if expires_at.tzinfo is None:
                    expires_at_dt = expires_at.replace(tzinfo=timezone.utc)
                else:
                    expires_at_dt = expires_at.astimezone(timezone.utc)
            else:
                # Fallback - assume it's a naive datetime and add UTC timezone
                expires_at_dt = datetime.fromisoformat(str(expires_at)).replace(tzinfo=timezone.utc)
            
            print(f"DEBUG: Expires at (converted): {expires_at_dt}")
            
            # Check if token is expired
            if current_time > expires_at_dt:
                print("DEBUG: Token has expired")
                flash('This reset link has expired. Please request a new one.')
                return redirect(url_for('forgot_password'))
            
            print("DEBUG: Token is valid, rendering reset password page")
            return render_template('reset_password.html', token=token, email=reset_data.get('email'))
            
        except Exception as e:
            print(f"ERROR in reset_password GET: {e}")
            import traceback
            traceback.print_exc()
            flash('An error occurred. Please try again.')
            return redirect(url_for('forgot_password'))
    
    elif request.method == 'POST':
        print("DEBUG: Processing POST request for password reset")
        
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        print(f"DEBUG: New password length: {len(new_password) if new_password else 0}")
        print(f"DEBUG: Passwords match: {new_password == confirm_password}")
        
        if not new_password or not confirm_password:
            flash('Please fill in all fields.')
            return render_template('reset_password.html', token=token)
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long.')
            return render_template('reset_password.html', token=token)
        
        if new_password != confirm_password:
            flash('Passwords do not match.')
            return render_template('reset_password.html', token=token)
        
        try:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            
            # Find and validate reset token
            resets_ref = db.collection('password_resets')
            reset_docs = list(resets_ref.where('token_hash', '==', token_hash).where('used', '==', False).get())
            
            print(f"DEBUG: Found {len(reset_docs)} reset docs for POST")
            
            if not reset_docs:
                print("DEBUG: No valid reset token found for POST")
                flash('Invalid or expired reset link.')
                return redirect(url_for('forgot_password'))
            
            reset_doc = reset_docs[0]
            reset_data = reset_doc.to_dict()
            
            # Check if token is expired (same logic as GET)
            from datetime import datetime, timezone
            current_time = datetime.now(timezone.utc)
            expires_at = reset_data['expires_at']
            
            # Convert expires_at to UTC datetime if needed
            if hasattr(expires_at, 'timestamp'):
                expires_at_dt = expires_at.replace(tzinfo=timezone.utc)
            elif isinstance(expires_at, datetime):
                if expires_at.tzinfo is None:
                    expires_at_dt = expires_at.replace(tzinfo=timezone.utc)
                else:
                    expires_at_dt = expires_at.astimezone(timezone.utc)
            else:
                expires_at_dt = datetime.fromisoformat(str(expires_at)).replace(tzinfo=timezone.utc)
            
            if current_time > expires_at_dt:
                print("DEBUG: Token expired during POST")
                flash('This reset link has expired. Please request a new one.')
                return redirect(url_for('forgot_password'))
            
            print(f"DEBUG: Updating password for user: {reset_data['user_id']}")
            
            # Update user password
            user_ref = db.collection('users').document(reset_data['user_id'])
            hashed_password = generate_password_hash(new_password)
            
            user_ref.update({
                'password': hashed_password,
                'password_updated_at': current_time
            })
            
            print("DEBUG: Password updated successfully")
            
            # Mark reset token as used
            reset_doc.reference.update({
                'used': True,
                'used_at': current_time
            })
            
            print("DEBUG: Reset token marked as used")
            
            flash('Your password has been updated successfully! You can now log in.')
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"ERROR in reset_password POST: {e}")
            import traceback
            traceback.print_exc()
            flash('An error occurred while resetting your password. Please try again.')
            return render_template('reset_password.html', token=token)

@app.route('/browse-subjects')
def browse_subjects():
    if 'user_id' not in session or session.get('role') != 'student':
        flash('Students only access.')
        return redirect(url_for('login'))
    
    try:
        # Get already enrolled subject IDs
        enrollments_ref = db.collection('enrollments').where('student_id', '==', session['user_id']).where('status', '==', 'active')
        enrolled_subject_ids = []
        
        for doc in enrollments_ref.stream():
            enrolled_subject_ids.append(doc.to_dict()['subject_id'])
        
        # Get all subjects not enrolled in
        available_subjects = []
        all_subjects_ref = db.collection('subjects')
        
        for doc in all_subjects_ref.stream():
            if doc.id not in enrolled_subject_ids:
                subject_data = doc.to_dict()
                subject_data['id'] = doc.id
                
                # Calculate topic count
                topics_ref = db.collection('topics').where('subject_id', '==', doc.id)
                topic_count = len(list(topics_ref.stream()))
                subject_data['topic_count'] = topic_count
                
                # Calculate quiz count
                quizzes_ref = db.collection('quizzes').where('subject_id', '==', doc.id).where('is_published', '==', True)
                quiz_count = len(list(quizzes_ref.stream()))
                subject_data['quiz_count'] = quiz_count
                
                available_subjects.append(subject_data)
        
        return render_template('browse_subjects.html', 
                             available_subjects=available_subjects,
                             username=session.get('username'))
    
    except Exception as e:
        print(f"Error fetching available subjects: {e}")
        flash('Error loading subjects.')
        return redirect(url_for('dashboard'))
    
if __name__ == '__main__':
    # app.run(debug=True)
    app.run(debug=True, host='0.0.0.0', port=5000)

