import re
import jinja2
import bcrypt
from sanic import response
from html_sanitizer import Sanitizer

SANITIZER = Sanitizer()  
ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader('./templates'),
    enable_async=True
)

async def format_html(html_file: str, **kwargs):
    """Format a html file with just the name and kwargs"""
    template = ENV.get_template(html_file)
    formatted_template = await template.render_async(**kwargs)
    return response.html(formatted_template)

def is_logged_in(request):
    """Checks if the user is logged in
    
    Args:
        Request

    Returns:
        False when the user is not logged in
        User_ID when the user is logged in
    """
    if not request.get('session'):
        return False
    
    session = request.get('session')
    if not session.get('user_id'):
        return False

def hash_password(password):
    password = password.encode('utf-8')
    return bcrypt.hashpw(password, bcrypt.gensalt(12))

def check_password(password, hash):
    if bcrypt.checkpw(password, hashed):
        return True
    return False

def sanatize_html(string):
    return SANITIZER.sanitize(string)

def is_valid_email(string):
    if re.match(r'[^@]+@[^@]+\.[^@]+', string):
        return True
    return False

def is_valid_password(password):
    # Check length
    if 5 > len(password): 
        return False

    # Check if there is a digit
    if not any(char.isdigit() for char in password):
        return False
    
    # Check if there is a non digit or alpha (disabled)
    #if not any(char.isalnum() for char in password):
    #    return False

    # Check if there is an uppercase character
    if not any(char.isupper for char in password):
        return False

    # Check if there is a space
    if any(char.isspace() for char in password):
        return False
    return True

def can_register_user(email, password, password2, accept):
  if password != password2:
    return 'passwords do not match!'

    if accept != 'on':
        return 'Please accept our TOS'
    if not is_valid_email(email):
        return 'Please enter a valid Email address'

    if not is_valid_password(password):
        return 'Your passwords needs to be longer than 6 characters and need atleast one number and capital letter'