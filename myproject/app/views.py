from django.shortcuts import render, redirect
from django.http import HttpRequest
from django.template import RequestContext
from datetime import datetime
from django.http import JsonResponse
from .main import validate_register
from .main import validate_login
from .fileValidate import validate_assignment
from .forgot_password import process_forgot_password
from .forgot_password import verify_token_and_update_password
from .changePassw import change_password
from .marks import process_marks_file
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.csrf import csrf_protect
from django.contrib.sessions.models import Session
import logging
from django.shortcuts import redirect
from django.contrib.auth import logout
from django.core.files.storage import FileSystemStorage
import json
import os
from django.conf import settings
from django.contrib.auth.decorators import login_required

# Your existing code...
def home(request):
    """Renders the home page."""
    assert isinstance(request, HttpRequest)
    if request.user.is_authenticated:
        return(redirect('/menu'))
    else:
        return render(
            request,
            'app/index.html',
            {
                'title':'Home Page',
                'year': datetime.now().year,
            }
        )

def contact(request):
    """Renders the contact page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/contact.html',
        {
            'title':'Contact',
            'message':'Dr. Yeoh.',
            'year':datetime.now().year,
        }
    )
    
# Set up logging
logger = logging.getLogger(__name__)

@csrf_exempt
def login_validation(request):
    try:
        if request.method == 'POST':
            # Call the login validation logic
            login_result = validate_login()
            
            # Handle successful login
            if login_result is True:
                return JsonResponse({'message': 'Login Successful!'})
            else:
                # Define error messages for login validation
                error_messages = {
                    'invalid_password_format': 'Invalid password format. {0}',  # Placeholder for dynamic message
                    'credentials_mismatch': 'User credentials do not match. Please check your Name, Email, and ID.',
                    'invalid_signature': 'Invalid format for signature.',
                    'invalid_ciphertext': 'Invalid format for ciphertext.',
                    'public_key_mismatch': 'Public key does not match. Please use the correct authentication method.',
                    'signature_verification_failed': 'Signature verification failed. Please check if you use the correct key pair for the registered public key.',
                    'decryption_failed': 'Unable to decrypt authentication credentials. Please check if you use the correct admin public key to encrypt.',
                    'unknown_error': 'An unknown error occurred during login. Please try again.',
                }
                
                # Handle dynamic error message for invalid_password_format
                if isinstance(login_result, tuple) and login_result[0] == 'invalid_password_format':
                    error_message = error_messages['invalid_password_format'].format(login_result[1])
                else:
                    # Get the error message based on the error name
                    error_message = error_messages.get(login_result, 'Unable to complete login. Please try again.')
                
                return JsonResponse({
                    'error': login_result,  # Return the error name
                    'message': error_message  # Return the mapped error message
                }, status=400)
        else:
            return JsonResponse({'error': 'Invalid request method'}, status=405)
    except Exception as e:
        logger.error(f"Error in login validation: {str(e)}")
        return JsonResponse({
            'error': 'system_error',
            'message': 'An unexpected error occurred. Please try again later.'
        }, status=500)

@csrf_protect
def register_validation(request):
    try:
        if request.method == 'POST':
            # Call the registration validation logic
            validation_result = validate_register()
            
            # Handle successful registration
            if validation_result is True:
                return JsonResponse({'message': 'Registration Successful!'})
            else:
                # Define error messages for registration validation
                error_messages = {
                    'name_id_not_found': 'Name or ID does not match our records.',
                    'already_registered': 'This account already exists and duplicate registration is not allowed.',
                    'email_exists': 'This email has already been used for registration.',
                    'unknown_error': 'Unable to complete registration. Please try again.'
                }
                
                # Get the error message based on the validation result
                error_message = error_messages.get(validation_result, error_messages['unknown_error'])
                
                return JsonResponse({
                    'error': validation_result,  # Return the error name
                    'message': error_message  # Return the mapped error message
                }, status=400)
        else:
            return JsonResponse({
                'error': 'Invalid request method',
                'message': 'Only POST requests are allowed.'
            }, status=405)
    except Exception as e:
        logger.error(f"Error in registration: {str(e)}")
        return JsonResponse({
            'error': 'system_error',
            'message': 'An unexpected error occurred. Please try again later.'
        }, status=500)

@csrf_protect
def assignment_validation(request):
    try:
        if request.method == 'POST':
            # Call the assignment validation logic
            aSubmission_result = validate_assignment()
            
            # Handle successful assignment submission
            if aSubmission_result is True:
                return JsonResponse({'message': 'Assignment Submission Successful!'})
            else:
                # Define error messages for assignment validation
                error_messages = {
                    'user_not_found': 'User not found in the system. Please check your email and ID.',
                    'decryption_failed': 'Unable to decrypt the submission link. Please ensure you used the correct encryption process or correct password',
                    'invalid_link_format': 'The submitted Google Drive link format is invalid. Please check the link format.',
                    'file_not_found': 'The submitted file or folder was not found. Please check if the link is correct and accessible.',
                    'empty_folder': 'The submitted folder is empty or system do not have permission to access it.',
                    'hash_mismatch': 'File content verification failed. Please ensure you submitted the correct hash & only one file in the folder.',
                    'firebase_update_failed': 'Your submission was validated but could not be saved. Please try again.',
                    'unknown_error': 'Unable to complete submission. Please try again.'
                }
                
                # Get the error message based on the submission result
                error_message = error_messages.get(aSubmission_result, error_messages['unknown_error'])
                
                return JsonResponse({
                    'error': aSubmission_result,  # Return the error name
                    'message': error_message  # Return the mapped error message
                }, status=400)
        else:
            return JsonResponse({
                'error': 'Invalid request method',
                'message': 'Only POST requests are allowed.'
            }, status=405)
    except Exception as e:
        logger.error(f"Error in assignment submission: {str(e)}")
        return JsonResponse({
            'error': 'system_error',
            'message': 'An unexpected error occurred. Please try again later.'
        }, status=500)

@csrf_protect
def forgot_password_validation(request):
    try:
        if request.method == 'POST':
            # Call the forgot password process
            forgot_result = process_forgot_password()
            
            # Handle the result based on the returned error code
            if forgot_result is True:
                return JsonResponse({'message': 'Forgot Password Validation Successful!'})
            else:
                error_messages = {
                'user_not_found': 'User not found in the system. Please check your name, email, ID, and public key.',
                'public_key_error': 'Failed to load public key. Please ensure your public key is valid.',
                'encryption_error': 'Failed to encrypt token. Please check your public key.',
                'firebase_error': 'Failed to store token in Firebase. Please try again later.',
                'email_error': 'Failed to send reset email. Please check your email address.',
                'system_error': 'An unexpected error occurred. Please try again later.',
            }
                # Get the error message based on the error name
                error_message = error_messages.get(forgot_result, 'Unable to complete submission. Please try again.')
                
                return JsonResponse({
                    'error': forgot_result,  # Return the error name
                    'message': error_message  # Return the mapped error message
                }, status=400)
    except Exception as e:
        logger.error(f"Error in forgot password validation: {str(e)}")
        return JsonResponse({
            'error': 'System error',
            'message': 'An unexpected error occurred. Please try again later.'
        }, status=500)
        
@csrf_protect
def validate_token(request):
    try:
        if request.method == 'POST':
            token_result = verify_token_and_update_password()
            
            if token_result is True:
                return JsonResponse({'message': 'Password updated successfully!'})
            elif isinstance(token_result, tuple) and token_result[0] == 'invalid_password_format':
                # Handle password validation errors
                return JsonResponse({
                    'error': 'invalid_password_format',
                    'message': token_result[1]  # Return the specific password error message
                }, status=400)
            else:
                # Map error names to error messages
                error_messages = {
                    'no_verification_data': 'No verification data found. Please submit the verification form again.',
                    'no_users_found': 'No users found in the database. Please try again later.',
                    'invalid_token_or_email': 'Invalid token or email. Please check your email and token.',
                    'token_expired': 'Token has expired. Please request a new password reset.',
                    'system_error': 'An unexpected error occurred. Please try again later.',
                    'invalid_signature': 'Signature verification failed. Please check if you use the correct key pair for the registered public key.',
                    'decryption_failed': 'Unable to decrypt authentication credentials. Please check if you use the correct admin public key to encrypt.',
                }
                
                # Get the error message based on the error name
                error_message = error_messages.get(token_result, 'Unable to complete submission. Please try again.')
                
                return JsonResponse({
                    'error': token_result,  # Return the error name
                    'message': error_message  # Return the mapped error message
                }, status=400)
    except Exception as e:
        logger.error(f"Error in token validation: {str(e)}")
        return JsonResponse({
            'error': 'system_error',  # Error name
            'message': 'An unexpected error occurred. Please try again later.'  # Error message
        }, status=500)

@csrf_protect
def change_password_validation(request):
    try:
        if request.method == 'POST':
            change_result = change_password()
            
            if change_result is True:
                return JsonResponse({'message': 'Password changed successfully!'})
            elif isinstance(change_result, tuple) and change_result[0] == 'invalid_password_format':
                # Handle password validation errors
                return JsonResponse({
                    'error': 'invalid_password_format',
                    'message': change_result[1]  # Return the specific password error message
                }, status=400)
            else:
                # Map error names to error messages
                error_messages = {
                    'no_firebase_data': 'Failed to fetch Firebase data. Please try again later.',
                    'no_password_change_data': 'Failed to fetch password change request data. Please try again.',
                    'missing_user_info': 'Missing required user information. Please check your input.',
                    'base64_decode_error': 'Error decoding base64 data. Please check your input.',
                    'admin_key_error': 'Failed to load admin private key. Please contact support.',
                    'user_key_error': 'User public key not found. Please contact support.',
                    'invalid_signature': 'Signature verification failed. Please check your input.',
                    'decryption_error': 'Failed to decrypt password. Please check your input.',
                    'invalid_old_password': 'Old password verification failed. Please check your input.',
                    'firebase_update_error': 'Failed to update password in Firebase. Please try again later.',
                    'user_not_found': 'No matching user found. Please check your email, id and name.',
                    'system_error': 'An unexpected error occurred. Please try again later.',
                }
                
                # Get the error message based on the error name
                error_message = error_messages.get(change_result, 'Unable to complete submission. Please try again.')
                
                return JsonResponse({
                    'error': change_result,  # Return the error name
                    'message': error_message  # Return the mapped error message
                }, status=400)
    except Exception as e:
        logger.error(f"Error in password change validation: {str(e)}")
        return JsonResponse({
            'error': 'system_error',  # Error name
            'message': 'An unexpected error occurred. Please try again later.'  # Error message
        }, status=500)
        
# Define the path for the grades file
GRADES_FILE = os.path.join(settings.BASE_DIR, 'grades_storage.json')
@csrf_exempt
def handle_file_upload(request):
    if request.method == 'POST' and request.FILES.get('gradingFile'):
        try:
            # Get the uploaded file
            uploaded_file = request.FILES['gradingFile']
            fs = FileSystemStorage()
            
            # Save the uploaded file temporarily
            filename = fs.save(uploaded_file.name, uploaded_file)
            file_path = fs.path(filename)
            
            # Process the file and get encrypted data
            encrypted_data = process_marks_file(file_path)
            
            # Clean up the temporary file
            fs.delete(filename)
            
            if encrypted_data:
                # Save encrypted data to JSON file
                with open(GRADES_FILE, 'w') as f:
                    json.dump({
                        'grades': encrypted_data,
                        'timestamp': str(datetime.now())
                    }, f)
                
                return JsonResponse({
                    'status': 'success',
                    'message': 'File processed and saved successfully',
                })
            else:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Error processing file'
                }, status=500)
                
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    else:
        return JsonResponse({
            'status': 'error',
            'message': 'No file uploaded'
        }, status=400)

@csrf_exempt
def clear_grades(request):
    if request.method == 'POST':
        try:
            if os.path.exists(GRADES_FILE):
                # Option 1: Delete the file
                #os.remove(GRADES_FILE)
                
                # Option 2: Or clear the contents by writing empty data
                with open(GRADES_FILE, 'w') as f:
                    json.dump({'grades': [], 'timestamp': str(datetime.now())}, f)
                
                return JsonResponse({
                    'status': 'success',
                    'message': 'Grades cleared successfully'
                })
            else:
                return JsonResponse({
                    'status': 'success',
                    'message': 'No grades to clear'
                })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    }, status=400)
        
def about(request):
    """Renders the about page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/about.html',
        {
            'title':'ABC System',
            'message':'This application processes ...',
            'year':datetime.now().year,
        }
    )

def forgotPassword(request):
    """Renders the about page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/forgotPassword.html'
    )

def changePassword(request):
    """Renders the about page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/changePassword.html'
    )
    
def tokenValidation(request):
    """Renders the about page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/tokenValidation.html'
    )
    
def assignment(request):
    """Renders the about page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/assignment.html'
    )
    
def login(request):
    """Renders the about page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/login.html'
)
    
def registration(request):
    """Renders the about page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/registration.html'
)
    
def grading(request):
    try:
        # Check if grades file exists
        if os.path.exists(GRADES_FILE):
            with open(GRADES_FILE, 'r') as f:
                data = json.load(f)
                grades = data.get('grades', [])
        else:
            grades = []
            
        return render(request, 'app/grading.html', {'grades': grades})
    except Exception as e:
        return render(request, 'app/grading.html', {'grades': [], 'error': str(e)})
    
def upload(request):
    """Renders the about page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/upload.html'
)

@login_required
def menu(request):
    user_email = request.user.email  # Assumes the user model has an email field
    is_registered = validate_login(user_email)

    if not is_registered:
        return redirect('/registration')  # Redirect if not registered

    context = {
        'title': 'Main Menu',
        'is_employee': request.user.groups.filter(name='employee').exists(),
        'year': datetime.now().year,
    }
    context['user'] = request.user

    return render(request, 'app/menu.html', context)
