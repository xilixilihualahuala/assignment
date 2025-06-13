# app/utils/firebase_init.py

import firebase_admin
from firebase_admin import credentials, db
from google.oauth2.service_account import Credentials
import gspread
from googleapiclient.discovery import build
import logging
import os
from django.conf import settings

# Set up logging
logger = logging.getLogger(__name__)

class FirebaseGoogleInit:
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(FirebaseGoogleInit, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not FirebaseGoogleInit._initialized:
            try:
                # Get the base directory path (this will be the myproject directory)
                base_dir = settings.BASE_DIR
                
                # Initialize Firebase
                # Using path to root project directory where credentials are stored
                cred_path = os.path.join(base_dir, 'firebase-admin (2).json')
                cred = credentials.Certificate(cred_path)
                
                if not firebase_admin._apps:  # Check if Firebase isn't already initialized
                    firebase_admin.initialize_app(cred, {
                        "databaseURL": "https://fyp01-db222-default-rtdb.firebaseio.com"
                    })
                
                # Initialize Google Sheets
                sheets_cred_path = os.path.join(base_dir, 'credentials.json')
                self.sheets_scopes = [
                    "https://www.googleapis.com/auth/spreadsheets", 
                    "https://www.googleapis.com/auth/drive.readonly",
                    "https://www.googleapis.com/auth/gmail.send"  # Add this line
                ]
                self.sheets_creds = Credentials.from_service_account_file(
                    sheets_cred_path, 
                    scopes=self.sheets_scopes
                )
                self.sheets_client = gspread.authorize(self.sheets_creds)
                
                # Initialize Google Drive
                # Note: You might need to adjust this path if credentials.json is in a different location
                drive_cred_path = os.path.join(base_dir, 'credentials.json')  # Using the same credentials file
                self.drive_creds = Credentials.from_service_account_file(
                    drive_cred_path,
                    scopes=['https://www.googleapis.com/auth/drive.readonly']
                )
                self.drive_service = build('drive', 'v3', credentials=self.drive_creds)
                
                # Initialize Firebase reference
                self.db_ref = db.reference('users')
                
                FirebaseGoogleInit._initialized = True
                logger.info("Firebase and Google services initialized successfully")
                
            except Exception as e:
                logger.error(f"Error initializing Firebase and Google services: {str(e)}")
                raise

    def get_db_ref(self):
        return self.db_ref
    
    def get_sheets_client(self):
        return self.sheets_client
    
    def get_drive_service(self):
        return self.drive_service