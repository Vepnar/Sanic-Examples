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
    if not request.get('session'):
        return False
    
    session = request.get('session')
    if not session.get('user_id'):
        return False

def hash_password(password):
    return bcrypt.hashpw(password, bcrypt.gensalt(10))

def check_password(password, hash):
    if bcrypt.checkpw(password, hashed):
        return True
    return False

def sanatize_html(string):
    return SANITIZER.sanitize(string)