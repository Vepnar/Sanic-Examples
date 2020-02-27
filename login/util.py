# pylint: disable=E0401, W0614, W0401
"""Utilities we use everywere in our program"""
import re
import bcrypt
import jinja2

from sanic import response
from models import UserModel
from html_sanitizer import Sanitizer

SANITIZER = Sanitizer()  
ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader('./templates'),
    enable_async=True
)

async def format_html(html_file: str, **kwargs):
    """Format a html file with just the name and kwargs"""
    template = ENV.get_template(html_file)

    # Check is user is logged in
    if 'request' in kwargs:
        request = kwargs.get('request')
        user = is_logged_in(request)
        if user:
            kwargs.update({'user' : user})

    formatted_template = await template.render_async(**kwargs)
    return response.html(formatted_template)

def is_logged_in(request) -> object:
    """Checks if the user is logged in
    
    Returns:
        False when the user is not logged in
        User_ID when the user is logged in
    """
    if not request.get('session'):
        return None
    
    session = request.get('session')
    if not session.get('user_id'):
        return None
    return session.get('user_id')

def hash_password(password: str) -> bytes:
    """Hash a new password"""
    password = password.encode('utf-8')
    return bcrypt.hashpw(password, bcrypt.gensalt(12))

def check_password(password : str, hashed : bytes) -> bool:
    """Check if the given password matches with the stored password"""
    password = password.encode('utf-8')
    if bcrypt.checkpw(password, hashed):
        return True
    return False

def sanatize_html(string: str) -> str:
    """Sanatize html strings"""
    return SANITIZER.sanitize(string)

def is_valid_email(string):
    """Checks if the given email address is a real address"""
    if re.match(r'[^@]+@[^@]+\.[^@]+', string):
        return True
    return False

def is_valid_password(password: str) -> bool:
    """Check if the given password fits the requirements"""
    if len(password) < 5: 
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

def can_register_user(email: str, password: str, password2: str, accept: str) -> str:
    """Tries if the user can register on our website

    Exceptions:
    - passwords don't match
    - password doesn't fit the requirements
    - email already exists
    - TOS not accepted

    """
    if password != password2:
        return 'passwords do not match!'

    if accept != 'on':
        return 'Please accept our TOS'
    if not is_valid_email(email):
        return 'Please enter a valid Email address'

    if not is_valid_password(password):
        return 'Your passwords needs to be longer than 6 characters and need atleast one number and capital letter'

    if UserModel.objects(email=email):
        return 'This email is already registed'
    return None

def attempt_login(email: str, password: str) -> object:
    """Attempt to login on an user.
    
    Args:
        email: an email address of an user who has an account on our service.
        password: the password the user has given.

    Returns:
        Returns user object when the user exists.
        Or returns nothing when the user doesn't exist.

    Note:
        This task is heavy on the cpu because it hashes the password with bcrypt
    """

    users = UserModel.objects(email=email)
    if not users:
        return None
    users = users[0]
    if check_password(password, users.password):
        return users

