import os
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, firestore

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    
    # Email configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'jezreelramoz@gmail.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'xkdc lagb xlkk lrkz'  # Use Gmail App Password
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_USERNAME') or 'jezreelramoz@gmail.com'
    MAIL_MAX_EMAILS = None
    MAIL_SUPPRESS_SEND = False  # Set to True in testing
    MAIL_ASCII_ATTACHMENTS = False

# Initialize Firebase
def init_firebase():
    if not firebase_admin._apps:
        # You'll need to download your Firebase service account key
        # and place it in your project root as 'firebase-key.json'
        cred = credentials.Certificate('firebase-key.json')
        firebase_admin.initialize_app(cred)
    
    return firestore.client()

# Initialize Firestore client
db = init_firebase()