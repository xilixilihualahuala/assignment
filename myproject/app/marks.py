import logging
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pandas as pd
import base64
from .utils.firebase_init import FirebaseGoogleInit

# Set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Initialize Firebase
firebase_google = FirebaseGoogleInit()
db_ref = firebase_google.get_db_ref()

def fetch_public_key_by_name(name):
    """Fetch the public key from Firebase database based on the name."""
    try:
        data = db_ref.get()
        if data:
            for key, value in data.items():
                if value.get('Name') == name:
                    public_key = value.get('PublicKey')
                    if public_key:
                        return public_key
        return None
    except Exception as e:
        logger.error(f"Error fetching data from Firebase: {e}")
        return None

def load_public_key(public_key_str):
    """Load the public key from a base64-encoded DER format string"""
    try:
        public_key_der = base64.b64decode(public_key_str)
        public_key = serialization.load_der_public_key(public_key_der)
        return public_key
    except Exception as e:
        logger.error(f"Error loading public key: {str(e)}")
        return None

def encrypt_mark(student_name, mark, public_key):
    """Encrypt the student's mark using their public key"""
    try:
        message = f"{student_name}:{mark}".encode('utf-8')
        
        encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        return None

def process_marks_file(input_file):
    """Process marks file and return encrypted data"""
    try:
        # Read input file
        if input_file.endswith('.xlsx'):
            df = pd.read_excel(input_file)
        else:
            df = pd.read_csv(input_file)
        
        encrypted_df = df.copy()
        
        for index, row in df.iterrows():
            student_name = row['Name']
            mark = row['Marks']
            
            # Fetch and load public key
            public_key_str = fetch_public_key_by_name(student_name)
            if not public_key_str:
                continue
                
            public_key = load_public_key(public_key_str)
            if not public_key:
                continue
            
            # Encrypt mark
            encrypted_mark = encrypt_mark(student_name, mark, public_key)
            if encrypted_mark:
                encrypted_df.at[index, 'Marks'] = str(encrypted_mark)
        
        # Return the DataFrame
        return encrypted_df.to_dict('records')
    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        return None