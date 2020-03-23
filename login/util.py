# pylint: disable=E0401, W0614, W0401
"""Utilities we use everywere in our program"""
import re
import jinja2
import string

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

def sanitize_html(html: str, sanitize_level=0) -> str:
    """sanitize html and remove possible injections with different security.
    
    Args:
        html: the string you want to sanitize
        sanitize: (0-2) the level you want to sanitize

    Levels:
        0: Remove all "<>"
        1: Replace <> with non injectable counterparts
        2: Remove all forbidden tags but leave some open

    Return: a sanitized version of the given string
    """
    if sanitize_level == 1: # Remove <> and replace them with their non dangerous counterparts
        return html.replace('<', '&lt;').replace('>', '&gt;')
    if sanitize_level == 2: # Remove all dangerous injections 
        return SANITIZER.sanitize(html)
    return html.translate(None, "<>") # Remove <>


def is_valid_email(string):
    """Checks if the given email address is a real address"""
    if re.match(r'[^@]+@[^@]+\.[^@]+', string):
        return True
    return False

def is_valid_password(password):
    """Check if the given password fits the requirements
    
    Args: 
        Password: the string you want to check 

    Requirements:
        The string has to be longer than 5
        The string contains at least one non letter
        The string contains at least one uppercase character
    """
    if len(password) < 5: 
        return False

    # Check if there is any non letter
    if not any(char.alpha() for char in password):
        return False

    # Check if there is an uppercase character
    if not any(char.isupper for char in password):
        return False

    # Check if there is a space
    if any(char.isspace() for char in password):
        return False
    return True

# def can_register_user(email: str, password: str, password2: str, accept: str) -> str:
#     """Tries if the user can register on our website

#     Exceptions:
#     - passwords don't match
#     - password doesn't fit the requirements
#     - email already exists
#     - TOS not accepted

#     """
#     if password != password2:
#         return 'passwords do not match!'

#     if accept != 'on':
#         return 'Please accept our TOS'
#     if not is_valid_email(email):
#         return 'Please enter a valid Email address'

#     if not is_valid_password(password):
#         return 'Your passwords needs to be longer than 6 characters and need at least one number and capital letter'

#     if UserModel.objects(email=email):
#         return 'This email is already registed'
#     return None
