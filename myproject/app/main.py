
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import base64
from .utils.firebase_init import FirebaseGoogleInit
import hashlib
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

# Google Sheets IDs
REGISTRATION_SHEET_ID = os.getenv("REGISTRATION_SHEET_ID")
LOGIN_SHEET_ID = os.getenv("LOGIN_SHEET_ID")
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
# Paths for keys
ADMIN_PRIVATE_KEY_PATH = os.getenv("ADMIN_PRIVATE_KEY_PATH")
    
def verify_signature(public_key_str, data, signature):
    """
    Verify a signature using the provided public key string.
    
    :param public_key_str: PEM-formatted public key as a string
    :param data: Data that was signed (in bytes)
    :param signature: Signature to verify (in bytes)
    :return: Boolean indicating signature verification success
    """
    try:
        # Attempt to load the public key, handling potential formatting issues
        try:
            # First, try standard PEM loading
            public_key = serialization.load_pem_public_key(public_key_str.encode('utf-8'))
        except Exception as e:
            # If standard loading fails, try cleaning up the PEM format
            # Remove any header/footer and extra whitespace
            cleaned_key = '\n'.join([
                '-----BEGIN PUBLIC KEY-----',
                public_key_str.replace('-----BEGIN PUBLIC KEY-----', '')
                              .replace('-----END PUBLIC KEY-----', '')
                              .replace('\n', '')
                              .strip(),
                '-----END PUBLIC KEY-----'
            ])
            public_key = serialization.load_pem_public_key(cleaned_key.encode('utf-8'))
        
        # Verify the signature
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
        print(f"Signature verification failed: {e}")
        return False
    
def decrypt_ciphertext(private_key, ciphertext):
    try:
        # Decrypt using OAEP padding (matching the encryption method)
        decrypted_password = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_password
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

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
    

def fetch_last_login_data():
    """
    Fetch the last row of data from the Google Sheets login sheet.
    :return: A dictionary representing the last row
    """
    try:
        sheet = CLIENT.open_by_key(LOGIN_SHEET_ID).sheet1
        all_records = sheet.get_all_records()
        if all_records:
            last_row = all_records[-1]  # Fetch last row
            # Convert all values to strings to prevent data type issues
            last_row = {key: str(value) for key, value in last_row.items()}
            logger.info("Last login data from Google Sheets:")
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

def validate_login():
    """
    Comprehensive login validation:
    1. Fetch the last row of login data from Google Sheets
    2. Compare Name, Email, and ID with Firebase data
    3. Verify Public Key if credentials match
    :return: True if all validation checks pass, False otherwise
    """
    logger.info("Starting comprehensive login validation...")

    # Fetch login data from Google Sheets
    last_row = fetch_last_login_data()
    # Fetch existing Firebase data
    firebase_data = fetch_data_from_firebase()

    # Validate input data
    if not last_row or not firebase_data:
        logger.error("Login validation failed: Missing login or Firebase data.")
        return 'credentials_mismatch'

    # Extract login credentials from last row
    login_name = last_row.get('Name', '').strip()
    login_email = last_row.get('Email address', '').strip()
    login_id = str(last_row.get('ID', '')).strip()
    public_key = last_row.get('PublicKey', '').strip()
    login_public_key = remove_pem_headers(public_key)
    """try:
        login_signature = base64.b64decode(last_row.get('Signature', '').strip())
        login_ciphertext = base64.b64decode(last_row.get('Ciphertext', '').strip())
    except Exception as e:
        logger.error(f"Error decoding signature or ciphertext: {e}")
        return False"""
        
    try:
        login_signature = base64.b64decode(last_row.get('Signature', '').strip())
    except Exception as e:
        logger.error(f"Error decoding signature: {e}")
        return 'invalid_signature'

    try:
        login_ciphertext = base64.b64decode(last_row.get('Ciphertext', '').strip())
    except Exception as e:
        logger.error(f"Error decoding ciphertext: {e}")
        return 'invalid_ciphertext'

    # Comprehensive validation checks
    for key, value in firebase_data.items():
        # Debug print to show comparison details
        print("Comparing:")
        print(f"Login Name: '{login_name}', Firebase Name: '{str(value.get('Name', '')).strip()}'")
        print(f"Login Email: '{login_email}', Firebase Email: '{str(value.get('Email', '')).strip()}'")
        print(f"Login ID: '{login_id}', Firebase ID: '{str(value.get('ID', '')).strip()}'")
        
        # Modify comparison to be more flexible
        if (
            str(value.get('Name', '')).strip() == login_name and
            str(value.get('Email', '')).strip() == login_email and
            str(value.get('ID', '')).strip() == login_id
        ):
            # If credentials match, verify Public Key
            stored_public_key = value.get('PublicKey', '').strip()
            
              # Debug print to check public keys
            print("Stored Public Key:", repr(stored_public_key))
            print("Login Public Key:", repr(login_public_key))
            print("Public Keys Match:", stored_public_key == login_public_key)
            
            if login_public_key != stored_public_key:
                logger.warning("Login failed: Public Key mismatch.")
                return 'public_key_mismatch'
        
            # Proceed with signature verification
            try:
                if verify_signature(stored_public_key, login_ciphertext, login_signature):
                    # Load Admin Private Key for Decryption
                    admin_private_key = load_admin_private_key(ADMIN_PRIVATE_KEY_PATH)
                    if not admin_private_key:
                        logger.error("Failed to load admin private key.")
                        return 'decryption_failed'
                    
                    # Decrypt Ciphertext
                    decrypted_password = decrypt_ciphertext(admin_private_key, login_ciphertext)
                    if decrypted_password:
                        print("Decrypted password:", decrypted_password.decode('utf-8'))
                        # Convert decrypted password to string
                        decrypted_password_str = decrypted_password.decode('utf-8')
                        is_valid, error_message = validate_password_requirements(decrypted_password_str)
                        if not is_valid:
                            logger.warning(f"Password validation failed: {error_message}")
                            return 'invalid_password_format', error_message
                        
                        combine_text= decrypted_password_str + ADMIN_PASSWORD
                        # Hash the combined text
                        hashed_value = hashlib.sha256(combine_text.encode()).hexdigest()
                        #echo|set /p="444666HelloWorld" | openssl dgst -sha256 -->use this to run
                        try:
                            # Update the specific user node with the decrypted password
                            db_ref.child(key).update({
                                'Password': decrypted_password_str,
                                'Hash': hashed_value
                            })
                            logger.info(f"Decrypted password stored for user: {login_name}")
                        except Exception as e:
                            logger.error(f"Failed to store decrypted password in Firebase: {e}")
                        
                        logger.info("Login successful: Signature verified and ciphertext decrypted.")
                        return True
                else:
                    logger.warning("Login failed: Signature verification failed.")
                    return 'signature_verification_failed'
            except Exception as e:
                logger.error(f"Signature verification error: {e}")
                return 'signature_verification_failed'

    # No matching record found
    logger.info("Login failed: No matching credentials in Firebase.")
    return 'credentials_mismatch'


##########################################################################################
def fetch_last_register_data():
    """
    Fetch the last row of data from the Google Sheets registration sheet.
    :return: A dictionary representing the last row
    """
    try:
        sheet = CLIENT.open_by_key(REGISTRATION_SHEET_ID).sheet1
        all_records = sheet.get_all_records()
        if all_records:
            last_row = all_records[-1]  # Fetch last row
            # Convert all values to strings to prevent data type issues
            last_row = {key: str(value) for key, value in last_row.items()}
            logger.info("Last registration data from Google Sheets:")
            print(last_row)
            return last_row
        else:
            logger.info("No data found in the Google Sheet.")
            return {}
    except Exception as e:
        logger.error(f"Error fetching data from Google Sheets: {e}")
        return {}
    
def is_matching_and_save(last_row, firebase_data):
    try:
        for key, value in firebase_data.items():
            if (str(value.get('Name')) == str(last_row.get('Name')) and 
                str(value.get('ID')) == str(last_row.get('ID'))):
                
                # Check if email and public key is already set
                if value.get('Email') and value.get('PublicKey'):
                    logger.info(f"Registration attempt blocked for Name: {last_row.get('Name')}, ID: {last_row.get('ID')}")
                    return 'already_registered'
                
                public_key= last_row.get('PublicKey')
                store_public_key= remove_pem_headers(public_key)
                
                # If not registered, proceed with update
                db_ref.child(key).update({
                    'Email': last_row.get('Email'),
                    'PublicKey': store_public_key
                })
                logger.info(f"Data updated successfully for Name: {last_row.get('Name')}, ID: {last_row.get('ID')}")
                return True
        
        # No match found
        logger.info("No matching data found to update.")
        return 'name_id_not_found'

    except Exception as e:
        logger.error(f"Error during data validation and saving: {e}")
        return False

def validate_register():
    logger.info("Fetching and validating data...")

    last_row = fetch_last_register_data()
    firebase_data = fetch_data_from_firebase()

    if not last_row or not firebase_data:
        logger.info("Operation could not be performed due to missing data.")
        return False

    # Additional validation checks
    for key, value in firebase_data.items():
        # Check for exact match with existing registered email
        if value.get('Email') and value.get('Email') == last_row.get('Email'):
            logger.info(f"Email {last_row.get('Email')} already registered.")
            return 'email_exists'

    return is_matching_and_save(last_row, firebase_data)