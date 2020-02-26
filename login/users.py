import json
import session
from mongoengine import *
from sanic import response
from sanic import Blueprint

from util import format_html, hash_password

BLUEPRINT = Blueprint('users', url_prefix='/users')


class SessionModel(Document):
    """Store session information."""
    email = StringField(required=True, unique=True, max_length=32)
    passsword = BinaryField(required=True, max_length=60)
    created = DateTimeField(default=datetime.utcnow)
    last_login = DateTimeField(default=datetime.utcnow)
    role = StringField(required=True, default='member')    

@BLUEPRINT.get('/register')
async def register(request):
    return await format_html('register.html')

@BLUEPRINT.get('/')
async def index(request):
    return response.redirect('/users/login')

@BLUEPRINT.get('/test')
async def test(request):
    sessions = session.SessionModel.objects.count()
    does_have_session = request.get('session')
    hashed = hash_password(b'Hallo')
    error = f'Amount of TRASH: {sessions}<br>session: {does_have_session}<br>hash: {hashed} {len(hashed)}'
    return await format_html('error.html', error_code=200, error_message=error)

@BLUEPRINT.get('/login')
async def login(request):
    return await format_html('login.html')

