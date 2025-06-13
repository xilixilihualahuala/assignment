from .utils.firebase_init import FirebaseGoogleInit
import logging
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import string
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import time
import hashlib
import os
from google.oauth2.credentials import Credentials as GmailCredentials
from googleapiclient.discovery import build
import os
from dotenv import load_dotenv
load_dotenv()

# Set up logging
logger = logging.getLogger(__name__)

# Load sensitive configuration from environment variables
ADMIN_PRIVATE_KEY_PATH = os.getenv('ADMIN_PRIVATE_KEY_PATH')

# Gmail API configuration - Load from environment variables
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.send']
CLIENT_ID = os.getenv('GMAIL_CLIENT_ID')
CLIENT_SECRET = os.getenv('GMAIL_CLIENT_SECRET')
REDIRECT_URI = os.getenv('GMAIL_REDIRECT_URI')
REFRESH_TOKEN = os.getenv('GMAIL_REFRESH_TOKEN')

# Google Sheets IDs - Load from environment variables
PASSWORD_SHEET_ID = os.getenv('PASSWORD_SHEET_ID')
VERIFICATION_SHEET_ID = os.getenv('VERIFICATION_SHEET_ID')

# Email configuration
SENDER_EMAIL = os.getenv('SENDER_EMAIL')
SENDER_NAME = os.getenv('SENDER_NAME')
RESET_URL = os.getenv('RESET_URL', 'http://localhost:8000/tokenValidation')

# Admin password for hashing - Load from environment variable
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# Validation function for required environment variables
def validate_environment():
    """Validate that all required environment variables are set."""
    required_vars = [
        'GMAIL_CLIENT_ID',
        'GMAIL_CLIENT_SECRET', 
        'GMAIL_REFRESH_TOKEN',
        'PASSWORD_SHEET_ID',
        'VERIFICATION_SHEET_ID',
        'ADMIN_PASSWORD'
    ]
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {missing_vars}")
        raise ValueError(f"Missing required environment variables: {missing_vars}")
    
    logger.info("All required environment variables are set")

# Initialize Firebase and Google Sheets client
firebase_google = FirebaseGoogleInit()
CLIENT = firebase_google.get_sheets_client()
db_ref = firebase_google.get_db_ref()

def create_email_message(sender, to, subject, token, reset_url):
    """Create an email message with the encrypted token and reset button."""
    message = MIMEMultipart('alternative')
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject

    # Plain text version
    text_content = f"""
    Password Reset Request
    
    Your reset token: {token}
    
    Please visit {reset_url} to reset your password.
    """

    # HTML version with styled button
    html_content = f"""
    <html>
    <body>
        <h2>Password Reset Request</h2>
        <p>Your reset token:</p>
        <p style="background-color: #f5f5f5; padding: 10px; border-radius: 5px;">{token}</p>
        <a href="{reset_url}" 
           target="_blank"
           style="background-color: #4CAF50; color: white; padding: 10px 20px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px; border-radius: 5px;">
           Reset Password
        </a>
    </body>
    </html>
    """

    text_part = MIMEText(text_content, 'plain')
    html_part = MIMEText(html_content, 'html')
    
    message.attach(text_part)
    message.attach(html_part)
    
    return {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}

def send_reset_email(to_email, encrypted_token):
    """Send password reset email to the user."""
    try:
        # Validate environment variables before proceeding
        validate_environment()
        
        # Create Gmail credentials
        creds = GmailCredentials(
            None,
            refresh_token=REFRESH_TOKEN,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET
        )

        # Build Gmail service
        service = build('gmail', 'v1', credentials=creds)

        # Prepare email content
        sender = f"{SENDER_NAME} <{SENDER_EMAIL}>"
        subject = "Password Reset Request"
        
        # Create and send the message
        message = create_email_message(sender, to_email, subject, encrypted_token, RESET_URL)
        
        # Send the email
        result = service.users().messages().send(userId="me", body=message).execute()
        
        logger.info(f'Password reset email sent successfully to {to_email}. Message Id: {result["id"]}')
        return True

    except Exception as error:
        logger.error(f'Error sending password reset email: {error}')
        return 'email_error'  # Return error name instead of False

def fetch_data_from_firebase():
    """
    Fetch data from the Firebase database.
    :return: A dictionary of user data from Firebase
    """
    try:
        data = db_ref.get()
        if data:
            logger.info("Data fetched from Firebase:")
            #for key, value in data.items():
                #print(f"Key: {key}, Value: {value}")
        else:
            logger.info("No data found in Firebase.")
        return data
    except Exception as e:
        logger.error(f"Error fetching data from Firebase: {e}")
        return {}

def fetch_last_forgot_password_data():
    """
    Fetch the last row of data from the Google Sheets forgot password sheet.
    :return: A dictionary representing the last row
    """
    try:
        sheet = CLIENT.open_by_key(PASSWORD_SHEET_ID).sheet1
        all_records = sheet.get_all_records()
        if all_records:
            last_row = all_records[-1]  # Fetch last row
            # Convert all values to strings to prevent data type issues
            last_row = {key: str(value) for key, value in last_row.items()}
            logger.info("Last forgot password data from Google Sheets:")
            print(last_row)
            return last_row
        else:
            logger.info("No data found in the Google Sheet.")
            return {}
    except Exception as e:
        logger.error(f"Error fetching data from Google Sheets: {e}")
        return {}

def remove_pem_headers(public_key):
    """
    Remove PEM headers and footers from a public key.
    
    :param public_key: Public key string potentially with PEM headers
    :return: Base64 encoded public key without headers
    """
    # Remove begin and end markers
    public_key = public_key.replace('-----BEGIN PUBLIC KEY-----', '')
    public_key = public_key.replace('-----END PUBLIC KEY-----', '')
    
    # Remove whitespace and newlines
    public_key = ''.join(public_key.split())
    
    return public_key


def verify_credentials():
    """
    Verify if the submitted credentials match a record in Firebase with detailed logging.
    """
    logger.info("Starting credential verification...")

    # Fetch forgot password data from Google Sheets
    last_row = fetch_last_forgot_password_data()
    # Fetch existing Firebase data
    firebase_data = fetch_data_from_firebase()

    # Validate input data
    if not last_row or not firebase_data:
        logger.error("Credential verification failed: Missing input or Firebase data.")
        return 'user_not_found'

    # Extract and log all credentials from the last row
    submitted_name = last_row.get('Name', '').strip()
    submitted_email = last_row.get('Email address', '').strip()
    submitted_id = last_row.get('ID', '').strip()
    public_key = last_row.get('PublicKey', '').strip()
    
    if not all([submitted_name, submitted_email, submitted_id, public_key]):
        logger.error("Missing required fields in submission")
        return 'user_not_found'
        
    submitted_public_key = remove_pem_headers(public_key)

    # Check each record in Firebase
    for key, value in firebase_data.items():
        if not isinstance(value, dict):
            continue
            
        firebase_name = str(value.get('Name', '')).strip()
        firebase_email = str(value.get('Email', '')).strip()
        firebase_id = str(value.get('ID', '')).strip()
        firebase_public_key = str(value.get('PublicKey', '')).strip()

        if (firebase_email == submitted_email and
            firebase_name == submitted_name and
            firebase_id == submitted_id and
            firebase_public_key == submitted_public_key):
            
            logger.info("All credentials match!")
            return value  # Return the full user data dictionary

    logger.error("No matching credentials found in Firebase.")
    return 'user_not_found'

def generate_token(length=32):
    """
    Generate a secure random token.
    :param length: Length of the token to generate
    :return: Random token string
    
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))"""
    alphabet = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(alphabet) for _ in range(length))
    logger.info(f"Generated Token: {token}")
    return token

def load_public_key(public_key_str):
    """
    Load a public key from a string (without PEM headers).
    :param public_key_str: Public key content without headers
    :return: Public key object
    """
    try:
        # Reconstruct PEM format
        pem_header = "-----BEGIN PUBLIC KEY-----\n"
        pem_footer = "\n-----END PUBLIC KEY-----"
        
        # Remove all whitespace (spaces, newlines, etc.)
        public_key_str = public_key_str.replace(" ", "").replace("\n", "")
        
        # Format the key string with proper line breaks (every 64 characters)
        formatted_key = ""
        chunks = [public_key_str[i:i+64] for i in range(0, len(public_key_str), 64)]
        formatted_key = "\n".join(chunks)
        
        # Combine all parts
        complete_pem = pem_header + formatted_key + pem_footer
        
        # Debugging: Print the reconstructed PEM key
        print("Reconstructed PEM Key:")
        print(complete_pem)
        
        # Convert PEM string to public key object
        public_key = serialization.load_pem_public_key(
            complete_pem.encode('utf-8')
        )
        return public_key
    except Exception as e:
        print(f"Error loading public key: {str(e)}")
        return 'public_key_error'  # Return error name instead of None

def encrypt_token(token, public_key):
    """
    Encrypt the token using the user's public key.
    :param token: Token to encrypt
    :param public_key_str: User's public key content (without PEM headers)
    :return: Base64-encoded encrypted token
    """
    try:
        # Convert token to bytes if it's a string
        if isinstance(token, str):
            token = token.encode('utf-8')
            
        # Encrypt the data with the public key
        encrypted_data = public_key.encrypt(
            token,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Encode to base64 for easier handling
        return base64.b64encode(encrypted_data).decode('utf-8')
        
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return 'encryption_error'  # Return error name instead of None


def store_token_in_firebase(user_id, token, expiry_time):
    """
    Store the token and its expiry time in Firebase under the correct user node.
    :param user_id: User's Firebase ID
    :param token: Token to store
    :param expiry_time: Token expiry timestamp
    :return: Boolean indicating success
    """
    try:
        # Fetch all users from Firebase
        users = db_ref.get()
        
        if not users:
            logger.error("No users found in Firebase.")
            return False
        
        # Find the Firebase key for the user with the matching ID
        user_key = None
        for key, user_data in users.items():
            if isinstance(user_data, dict) and user_data.get('ID') == user_id:
                user_key = key
                break
        
        if not user_key:
            logger.error(f"No user found with ID: {user_id}")
            return False
        
        # Update the token under the correct user node
        db_ref.child(user_key).update({
            'token': token,
            'expiry': expiry_time,
            'created_at': int(time.time())
        })
        
        logger.info(f"Token stored in Firebase under user {user_id} (key: {user_key}): {token}")
        return True
    except Exception as e:
        logger.error(f"Error storing token in Firebase: {e}")
        return 'firebase_error'  # Return error name instead of False
    
def process_forgot_password():
    """
    Main function to handle forgot password flow with email integration.
    :return: String indicating the result (e.g., 'success', 'user_not_found', 'public_key_error', etc.)
    """
    try:
        # Verify credentials first
        user_data = verify_credentials()
        if isinstance(user_data, str):  # Check if it's an error string
            return user_data  # Return the error code directly
        
        # Generate and encrypt token
        token = generate_token()
        expiry_time = int(time.time()) + (60 * 60)  # 1 hour

        # Load and encrypt with public key
        public_key_obj = load_public_key(user_data.get('PublicKey', ''))
        if isinstance(public_key_obj, str):  # Check if it's an error string
            return public_key_obj
        
        encrypted_token = encrypt_token(token, public_key_obj)
        if isinstance(encrypted_token, str) and encrypted_token.startswith('encryption_error'):
            return encrypted_token

        # Store token in Firebase
        user_id = user_data.get('ID')
        store_result = store_token_in_firebase(user_id, token, expiry_time)
        if isinstance(store_result, str):  # Check if it's an error string
            return store_result

        # Send email with encrypted token
        user_email = user_data.get('Email')
        if not send_reset_email(user_email, encrypted_token):
            return 'email_error'

        return True  # Everything worked

    except Exception as e:
        logger.error(f"Error in forgot password process: {e}")
        return 'system_error'
    
####################################################################################################################
def load_admin_private_key(private_key_path):
    """Load a private key from a file."""
    try:
        with open(private_key_path, "rb") as private_key_file:
            return serialization.load_pem_private_key(
                private_key_file.read(), 
                password=None  # Set to None if the key is not encrypted
            )
    except Exception as e:
        logger.error(f"Error loading admin private key: {e}")
        return None
    
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
        
        # Ensure data and signature are in bytes
        if isinstance(data, str):
            data = base64.b64decode(data)
        if isinstance(signature, str):
            signature = base64.b64decode(signature)
            
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
        # Ensure ciphertext is in bytes
        if isinstance(ciphertext, str):
            try:
                ciphertext = base64.b64decode(ciphertext)
            except Exception:
                logger.error("Invalid ciphertext format")
                return None
            
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

def fetch_last_verification_data():
    """
    Fetch the last row of data from the Google Sheets forgot password sheet.
    :return: A dictionary representing the last row
    """
    try:
        sheet = CLIENT.open_by_key(VERIFICATION_SHEET_ID).sheet1
        all_records = sheet.get_all_records()
        if all_records:
            last_row = all_records[-1]  # Fetch last row
            # Convert all values to strings to prevent data type issues
            last_row = {key: str(value) for key, value in last_row.items()}
            logger.info("Last forgot password data from Google Sheets:")
            print(last_row)
            return last_row
        else:
            logger.info("No data found in the Google Sheet.")
            return {}
    except Exception as e:
        logger.error(f"Error fetching data from Google Sheets: {e}")
        return {}
    
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

####################################################################################################################
def cleanup_expired_tokens():
    """
    Clean up expired tokens from Firebase database.
    Should be run periodically (e.g., via a cron job or scheduled task).
    """
    try:
        # Fetch all users from Firebase
        users = db_ref.get()
        if not users:
            logger.info("No users found in database")
            return

        current_time = int(time.time())

        # Check each user for expired tokens
        for key, user_data in users.items():
            if isinstance(user_data, dict):
                token = user_data.get('token')
                expiry = user_data.get('expiry')
                
                # If user has token and it's expired, mark for cleanup
                if token and expiry and current_time > expiry:
                    logger.info(f"Cleaning up expired token for user {key}")
                    # Token has expired, remove it
                    db_ref.child(key).update({
                        'token': None,
                        'expiry': None,
                        'created_at': None,
                    })
                else:
                    logger.info("No expired tokens found")

    except Exception as e:
        logger.error(f"Error cleaning up expired tokens: {e}")
        return False

def verify_token_and_update_password():
    """
    Verify the token from verification form and update password if valid.
    """
    try:
        # Fetch the latest verification submission
        verification_data = fetch_last_verification_data()
        if not verification_data:
            return 'no_verification_data'  

        # Extract data from verification form
        submitted_token = verification_data.get('Token', '').strip()
        submitted_email = verification_data.get('Email address', '').strip()
        submitted_ciphertext = verification_data.get('Ciphertext (New Pass)', '').strip()
        submitted_signature = verification_data.get('Signature (New Pass)', '').strip()

        if not all([submitted_token, submitted_email, submitted_ciphertext, submitted_signature]):
            logger.error("Missing required verification data")
            return 'missing_verification_data'

        # Log the submitted data (excluding sensitive information)
        logger.info(f"Processing verification for email: {submitted_email}")
        
        # First, clean up any expired tokens
        cleanup_expired_tokens()

        # Fetch all users from Firebase
        users = db_ref.get()
        if not users:
            return 'no_users_found'  

        # Find the user with matching email and token
        user_key = None
        user_data = None
        for key, data in users.items():
            if isinstance(data, dict):
                firebase_email = data.get('Email', '').strip()
                firebase_token = data.get('token', '').strip()
        
                if firebase_email == submitted_email and firebase_token == submitted_token:
                    user_key = key
                    user_data = data
                    logger.info("User match found")
                    break

        if not user_key or not user_data:
            return 'invalid_token_or_email'  

        # Check token expiration
        current_time = int(time.time())
        token_expiry = user_data.get('expiry', 0)
        if current_time > token_expiry:
            return 'token_expired'  
        
        # Process password update
        try:
            admin_private_key = load_admin_private_key(ADMIN_PRIVATE_KEY_PATH)
            if not admin_private_key:
                return 'decryption_failed'

            # Verify signature before decryption
            signature_valid = verify_signature(
                user_data.get('PublicKey', ''),
                submitted_ciphertext,
                submitted_signature
            )
            
            if not signature_valid:
                logger.error("Signature verification failed")
                return 'invalid_signature'

            # Decrypt and validate new password
            try:
                decrypted_password = decrypt_ciphertext(
                    admin_private_key,
                    base64.b64decode(submitted_ciphertext)
                )
                if not decrypted_password:
                    return 'decryption_failed'
            except Exception as e:
                logger.error(f"Decryption error: {str(e)}")
                return 'decryption_failed'

            try:
                new_password = decrypted_password.decode('utf-8')
            except UnicodeDecodeError as e:
                logger.error(f"Password decode error: {str(e)}")
                return 'invalid_password_format'

            is_valid, error_message = validate_password_requirements(new_password)
            if not is_valid:
                return ('invalid_password_format', error_message)

            # Generate hash using admin password from environment variable
            combined_text = new_password + ADMIN_PASSWORD
            hashed_value = hashlib.sha256(combined_text.encode()).hexdigest()
             
            # Update password and clear token
            db_ref.child(user_key).update({
                'Password': new_password,
                'Hash': hashed_value,
                'token': None,
                'expiry': None,
                'created_at': None,
            })

            logger.info("Password updated successfully")
            return True

        except Exception as e:
            logger.error(f"Password update failed: {str(e)}")
            return 'password_update_failed'

    except Exception as e:
        logger.error(f"Token verification failed: {str(e)}")
        return 'system_error'