import logging
import gspread
import base64
from google.oauth2.service_account import Credentials
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import hashlib
from app.utils.firebase_init import FirebaseGoogleInit
import os
from dotenv import load_dotenv
load_dotenv()

# Set up logging with more detailed format
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

CHANGED_SHEET_ID = os.getenv("CHANGED_SHEET_id")
ADMIN_PRIVATE_KEY_PATH = os.getenv("ADMIN_PRIVATE_KEY_PATH")
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
# Initialize services using the singleton
firebase_google = FirebaseGoogleInit()
CLIENT = firebase_google.get_sheets_client()
db_ref = firebase_google.get_db_ref()

def fetch_data_from_firebase():
    """Fetch data from Firebase database with enhanced error handling."""
    try:
        data = db_ref.get()
        if data:
            logger.info("Successfully fetched data from Firebase")
            return data
        logger.warning("No data found in Firebase")
        return {}
    except Exception as e:
        logger.error(f"Error fetching data from Firebase: {e}")
        return {}

def load_admin_private_key(private_key_path):
    """Load admin private key with enhanced security checks."""
    try:
        with open(private_key_path, "rb") as private_key_file:
            key_data = private_key_file.read()
            if not key_data:
                raise ValueError("Empty private key file")
            return serialization.load_pem_private_key(key_data, password=None)
    except FileNotFoundError:
        logger.error(f"Admin private key file not found at {private_key_path}")
        return None
    except Exception as e:
        logger.error(f"Error loading admin private key: {e}")
        return None

def fetch_last_changed_password_data():
    """Fetch last password change request with validation."""
    try:
        sheet = CLIENT.open_by_key(CHANGED_SHEET_ID).sheet1
        all_records = sheet.get_all_records()
        if not all_records:
            logger.warning("No records found in password change sheet")
            return {}
        
        last_row = all_records[-1]
        return {key: str(value).strip() for key, value in last_row.items()}
    except Exception as e:
        logger.error(f"Error fetching data from Google Sheets: {e}")
        return {}

def verify_signature(public_key_str, data, signature):
    """Verify signature with improved error handling and logging."""
    try:
        if not public_key_str or not data or not signature:
            logger.error("Missing required parameters for signature verification")
            return False

        # Clean and format public key
        cleaned_key = '\n'.join([
            '-----BEGIN PUBLIC KEY-----',
            public_key_str.replace('-----BEGIN PUBLIC KEY-----', '')
                          .replace('-----END PUBLIC KEY-----', '')
                          .replace('\n', '')
                          .strip(),
            '-----END PUBLIC KEY-----'
        ])
        
        public_key = serialization.load_pem_public_key(cleaned_key.encode('utf-8'))
        
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False

def decrypt_ciphertext(private_key, ciphertext):
    """Decrypt ciphertext with improved error handling."""
    if not private_key or not ciphertext:
        logger.error("Missing required parameters for decryption")
        return None
        
    try:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return None

def validate_password_requirements(password):
    """
    Validate password meets all requirements:
    - At least 10 characters long
    - Contains uppercase letters
    - Contains lowercase letters
    - Contains numbers
    - Contains special characters
    
    Returns: (bool, str) tuple - (is_valid, error_message)
    """
    if len(password) < 10:
        return False, "Password must be at least 10 characters long"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
        
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
        
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
        
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character"
    
    return True, "Password meets all requirements"

def verify_user_credentials(firebase_data, last_row):
    """Verify user credentials with enhanced security checks."""
    try:
        # Extract and validate required fields
        email = last_row.get('Email address', '').strip()
        user_id = last_row.get('ID', '').strip()
        name = last_row.get('Name', '').strip()

        if not all([email, user_id, name]):
            logger.error("Missing required user information")
            return 'missing_user_info'  

        # Decode signatures and ciphertexts
        try:
            old_signature = base64.b64decode(last_row.get('Signature (Old Pass)', '').strip())
            old_ciphertext = base64.b64decode(last_row.get('Ciphertext (Old Pass)', '').strip())
            new_ciphertext = base64.b64decode(last_row.get('Ciphertext (New Pass)', '').strip())
            new_signature = base64.b64decode(last_row.get('Signature (New Pass)', '').strip())
        except Exception as e:
            logger.error(f"Error decoding base64 data: {e}")
            return 'base64_decode_error'  

        # Load admin private key once
        admin_private_key = load_admin_private_key(ADMIN_PRIVATE_KEY_PATH)
        if not admin_private_key:
            logger.error("Failed to load admin private key")
            return 'admin_key_error'  

        # Find and verify user
        user_found = False
        for key, value in firebase_data.items():
            if all([
                str(value.get('Name', '')).strip() == name,
                str(value.get('Email', '')).strip() == email,
                str(value.get('ID', '')).strip() == user_id
            ]):
                user_found = True
                stored_public_key = value.get('PublicKey', '').strip()
                if not stored_public_key:
                    logger.error("User public key not found")
                    return 'user_key_error'  

                try:
                    if not verify_signature(stored_public_key, old_ciphertext, old_signature):
                        logger.error("Signature verification failed")
                        return 'invalid_signature'  

                    # Decrypt and verify old password
                    old_password = decrypt_ciphertext(admin_private_key, old_ciphertext)
                    if not old_password:
                        logger.error("Failed to decrypt old password")
                        return 'decryption_error'  
                    
                    old_password_str = old_password.decode('utf-8')
                    if old_password_str != value.get('Password', '').strip():
                        logger.error("Old password verification failed")
                        return 'invalid_old_password'
                    
                    if not verify_signature(stored_public_key, new_ciphertext, new_signature):
                        logger.error("Signature verification failed")
                        return 'invalid_signature'  

                    # Decrypt new password
                    new_password = decrypt_ciphertext(admin_private_key, new_ciphertext)
                    if not new_password:
                        logger.error("Failed to decrypt new password")
                        return 'decryption_error' 

                    new_password_str = new_password.decode('utf-8')
                    is_valid, error_message = validate_password_requirements(new_password_str)
                    if not is_valid:
                        logger.error(f"Password validation failed: {error_message}")
                        return ('invalid_password_format', error_message)

                    # Update password and hash in Firebase
                    try:
                        combined_text = new_password_str + ADMIN_PASSWORD
                        hashed_value = hashlib.sha256(combined_text.encode()).hexdigest()
                        db_ref.child(key).update({
                            'Password': new_password_str,
                            'Hash': hashed_value
                        })
                        logger.info("Password changed successfully")
                        return True  # Success
                    except Exception as e:
                        logger.error(f"Failed to update password in Firebase: {e}")
                        return 'firebase_update_error'  
                except Exception as e:
                    logger.error(f"Signature verification error: {e}")
                    return 'signature_verification_failed'
        
        if not user_found:
            logger.warning(f"No matching user found for ID {user_id}")
            return 'user_not_found'

    except Exception as e:
        logger.error(f"Error during user verification: {e}")
        return 'system_error'  

def change_password():
    """Main password change function with improved flow control."""
    try:
        # Fetch required data
        firebase_data = fetch_data_from_firebase()
        if not firebase_data:
            logger.error("Failed to fetch Firebase data")
            return 'no_firebase_data'  

        last_row = fetch_last_changed_password_data()
        if not last_row:
            logger.error("Failed to fetch password change request data")
            return 'no_password_change_data'  

        # Verify and change password
        result = verify_user_credentials(firebase_data, last_row)
        
        # Return the result directly, whether it's True, a tuple, or an error string
        return result

    except Exception as e:
        logger.error(f"Unexpected error during password change: {e}")
        return 'system_error'