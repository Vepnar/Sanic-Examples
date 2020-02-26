import json
import session

from mongoengine import *
from sanic import response
from sanic import Blueprint
from util import *

from datetime import datetime


BLUEPRINT = Blueprint('users', url_prefix='/users')


class UserModel(Document):
    """Store session information."""
    email = StringField(required=True, unique=True, max_length=32)
    password = BinaryField(required=True, max_length=60)
    created = DateTimeField(default=datetime.utcnow)
    last_login = DateTimeField(default=datetime.utcnow)
    role = StringField(required=True, default='member')   

@BLUEPRINT.get('/register')
async def register(request):
    return await format_html('register.html')

@BLUEPRINT.post('/register')
async def register_post(request):
    required = ['email', 'pwd-1', 'pwd-2', 'accept']
    if not all(item in request.form for item in required):
        return await format_html('register.html', error_message='Please accept our TOS')

    email = request.form.get('email', '').lower()
    password = request.form.get('pwd-1')
    password2 = request.form.get('pwd-2')
    accept = request.form.get('accept')

    
    message = can_register_user(email, password, password2, accept)
    if message is not None:
        return await format_html(
            'register.html', error_message=message, email=email
            )

    if UserModel.objects(email=email):
        return await format_html(
            'register.html', error_message='This email is already registed', email=email
            )

    hashed_password = hash_password(password)
    new_user = UserModel(email=email, password=hashed_password)
    new_user.save()

    request['session']['user_id'] = new_user.id
    return await format_html('register.html',error_message=new_user.id)

@BLUEPRINT.get('/')
async def index(request):
    return response.redirect('/users/login')

@BLUEPRINT.get('/test')
async def test(request):
    sessions = session.SessionModel.objects.count()
    users = UserModel.objects.count()
    does_have_session = request.get('session')
    user_id = request['session'].get('user_id')
    error = f'''
    Amount of session: {sessions}<br>
    Amount of users: {users}<br>
    session: {does_have_session}<br>
    user_id: {user_id}'''

    return await format_html('error.html', error_code=200, error_message=error)

@BLUEPRINT.get('/login')
async def login(request):
    return await format_html('login.html')

