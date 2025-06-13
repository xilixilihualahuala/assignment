import logging
from google.oauth2 import service_account
from googleapiclient.discovery import build
import io
from googleapiclient.http import MediaIoBaseDownload
import hashlib
import base64
import re
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64
import os
from .utils.firebase_init import FirebaseGoogleInit
import time  # Import the time module
import os
from dotenv import load_dotenv
load_dotenv()

# Set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Initialize services
firebase_google = FirebaseGoogleInit()
CLIENT = firebase_google.get_sheets_client()
db_ref = firebase_google.get_db_ref()
drive_service = firebase_google.get_drive_service()

# Constants
ASSIGNMENT_SHEET_ID = os.getenv("ASSIGNMENT_SHEET_ID")

# Set up Google Drive service
drive_creds = service_account.Credentials.from_service_account_file(
    "credentials.json", 
    scopes=['https://www.googleapis.com/auth/drive.readonly']
)
drive_service = build('drive', 'v3', credentials=drive_creds)


def fetch_last_assignment_data():
    """Fetch the last row from Google Sheets."""
    try:
        sheet = CLIENT.open_by_key(ASSIGNMENT_SHEET_ID).sheet1
        all_records = sheet.get_all_records()
        if all_records:
            last_row = all_records[-1]
            return {key: str(value).strip() for key, value in last_row.items()}
        return {}
    except Exception as e:
        logger.error(f"Error fetching from Google Sheets: {e}")
        return {}

def fetch_user_data(email, student_id):
    """Fetch specific user data from Firebase."""
    try:
        users = db_ref.get()
        for user_id, user_data in users.items():
            if (str(user_data.get('Email', '')).strip() == email and 
                str(user_data.get('ID', '')).strip() == student_id):
                return user_data
        return None
    except Exception as e:
        logger.error(f"Error fetching user data: {e}")
        return None

def derive_key_and_iv(password, salt):
    """
    Derive key and IV using PBKDF2
    """
    kdf = PBKDF2(password, salt, 48, 10000, hmac_hash_module=SHA256)
    key_iv = kdf
    return key_iv[:32], key_iv[32:48]

def decrypt_openssl_comaptible(encrypted_text, password):
    try:
        # Only allow valid base64 characters and validate
        valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n')
        if not all(c in valid_chars for c in encrypted_text):
            raise ValueError("Invalid characters detected in encrypted text")
            
        # Remove newlines and spaces
        cleaned_text = ''.join(encrypted_text.split())
        
        # Verify the Base64 format
        if len(cleaned_text) % 4 != 0:
            raise ValueError("Invalid Base64 length")
            
        try:
            password = password.encode('utf-8')
            encrypted_data = base64.b64decode(cleaned_text)  # Use cleaned_text here!
        except Exception as e:
            raise ValueError(f"Base64 decoding failed: {str(e)}")
            
        if len(encrypted_data) < 16:
            raise ValueError("Encrypted data too short")
            
        salt = encrypted_data[8:16]
        encrypted_data = encrypted_data[16:]
        
        key, iv = derive_key_and_iv(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)
        
        padding_len = decrypted[-1]
        if padding_len > 16 or padding_len > len(decrypted):
            raise ValueError("Invalid padding")
            
        decrypted = decrypted[:-padding_len]
        
        # Clean and decode the result
        if isinstance(decrypted, bytes):
            decrypted = decrypted.decode('utf-8')
        
        decrypted = decrypted.strip().strip('"').strip()
        
        print(f"Decrypted result (raw): {decrypted}")
        
        if 'drive.google.com' in decrypted:
            return decrypted.lstrip('-n ').strip('"').strip()
        else:
            raise ValueError("Decrypted link doesn't contain 'drive.google.com'")
            
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return None

def get_drive_file_id(link):
    """Extract file/folder ID from Google Drive link."""
    folder_match = re.search(r'folders/([a-zA-Z0-9-_]+)', link)
    print(f"Folder match result: {folder_match}")
    
    if folder_match:
        folder_id = folder_match.group(1)
        print(f"Found folder ID: {folder_id}")
        return folder_match.group(1), 'folder'
        
    file_match = re.search(r'file/d/([a-zA-Z0-9-_]+)', link)
    print(f"File match result: {file_match}")
    
    if file_match:
        file_id = file_match.group(1)
        print(f"Found file ID: {file_id}")
        return file_match.group(1), 'file'
        
    return None, None

def check_drive_content(file_id, content_type):
    """Check if Drive folder has files or if file exists."""
    try:
        if content_type == 'folder':
            # Check folder contents
            results = drive_service.files().list(
                q=f"'{file_id}' in parents",
                fields="files(id, name)"
            ).execute()
            files = results.get('files', [])
            if not files:
                return "empty"
            return "valid"
        else:
            # Check if file exists and is accessible
            try:
                drive_service.files().get(fileId=file_id).execute()
                return "valid"
            except Exception as e:
                logger.error(f"Unexpected file error: {e}")
                return "not_found"
    except Exception as e:
        logger.error(f"Error checking drive content: {e}")
        return "error"

def calculate_file_hash(file_id):
    #Calculate SHA-256 hash of file content in chunks.
    try:
        request = drive_service.files().get_media(fileId=file_id)
        file_hash = hashlib.sha256()
        fh = io.BytesIO()  # Create an in-memory byte stream to hold the downloaded file

        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()
            if status:
                print(f"Download {int(status.progress() * 100)}%.")
            fh.seek(0)  # Move to the beginning of the stream
            file_hash.update(fh.read())  # Update the hash with the chunk of data
            fh.seek(0)  # Reset stream position for next chunk

        # Return the final hash
        return file_hash.hexdigest()

    except Exception as e:
        logger.error(f"Error calculating hash: {e}")
        return None
"""
def calculate_file_hash(file_id):
    #Calculate hash of file content.
    try:
        file_content = drive_service.files().get_media(fileId=file_id).execute()
        return hashlib.sha256(file_content).hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash: {e}")
        return None"""

def validate_assignment():
    """Main function to validate assignment submission."""
    validation_start = time.time()
    # Get submission data
    submission = fetch_last_assignment_data()

    # Extract submission details
    email = submission.get('Email address', '')
    student_id = submission.get('ID', '')
    submitted_hash = submission.get('Hash', '')
    encrypted_link = submission.get('Encrypted File', '')
    timestamp = submission.get('Timestamp', '')

    print("\nValidation Process:")
    print(f"Processing submission for Email: {email}, ID: {student_id}")

    # Step 1: Verify user and get password
    user_data = fetch_user_data(email, student_id)
    if not user_data:
        print(f"❌ User not found: {email}")
        return 'user_not_found'

    # Step 2: Decrypt drive link
    password = user_data.get('Password')
    decrypted_result = decrypt_openssl_comaptible(encrypted_link, password)
    if decrypted_result is None:
        print(f"❌ Failed to decrypt link for {email}")
        return 'decryption_failed'

    # Step 3: Validate drive content
    file_id, content_type = get_drive_file_id(decrypted_result)
    if not file_id:
        print(f"❌ Invalid drive link format")
        return 'invalid_link_format'

    content_status = check_drive_content(file_id, content_type)
    if content_status != "valid":
        if content_status == "not_found":
            return 'file_not_found'
        elif content_status == "empty":
            return 'empty_folder'
        else:
            return 'invalid_link_format'

    # Step 4: Get file ID for hash calculation
    if content_type == 'folder':
        results = drive_service.files().list(
            q=f"'{file_id}' in parents",
            fields="files(id)"
        ).execute()
        files = results.get('files', [])
        file_id = files[0]['id']
    
    validation_end = time.time()
    print(f"Initial validation time: {validation_end - validation_start:.2f} seconds")

    # Step 5: Verify file hash
    hash_start = time.time()
    calculated_hash = calculate_file_hash(file_id)
    if calculated_hash != submitted_hash:
        print("❌ Hash mismatch")
        return 'hash_mismatch'
    hash_end = time.time()
    print(f"Hash calculation time: {hash_end - hash_start:.2f} seconds")
    
    upload_start = time.time()
    try:
        # Update Firebase
        data = db_ref.get()
        for key, data in data.items():
            if data.get('Email') == email:
                db_ref.child(key).update({
                    'Assignment': decrypted_result,
                    'timestamp': timestamp
                })
    except Exception as e:
        print(f"❌ Failed to update decrypted link: {e}")
        return 'firebase_update_failed'
    upload_end = time.time()
    print(f"Firebase update time: {upload_end - upload_start:.2f} seconds")
    total_time = time.time() - validation_start
    print(f"\nTotal process time: {total_time:.2f} seconds")

    print("\n✅ All validations passed successfully!")
    return True