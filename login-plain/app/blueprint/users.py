# pylint: disable=E0401, W0614, W0401, E0602, R0903
"""Handle users information with mongodb

This will be updated to an asynchronous alternative.
"""
import bcrypt
import asyncio


from functools import wraps
from datetime import datetime
from sanic import Blueprint, response
from mongoengine import (
    Document, StringField, BinaryField, DateTimeField, ListField, ReferenceField, PULL
)

from util.user_util import password_check_weak

BLUEPRINT = Blueprint('user', url_prefix='user')
APP = None


def Userhandler(app):
    global APP
    APP = app

class UserModel(Document):
    """Basic user database model with roles"""
    name = StringField(required=True, unique=True, max_length=32)
    password = BinaryField(required=True, max_length=60)
    created = DateTimeField(default=datetime.utcnow)
    last_login = DateTimeField(default=datetime.utcnow)
    role = ListField(StringField())

    @classmethod
    def login(cls, username, password):
        """Find a user matching the given username and try to login.
        Args:
            username: an username of an user who has an account on our service.
            password: the password the user has given.

        Returns:
            Returns user object when the user exists.
            Or returns nothing when the user doesn't exist.

        Note:
            This task is heavy on the cpu because it hashes the password with bcrypt.
        """
        users = cls.objects(name__exact=username)
        if not users:  # Return no user when there is no matching E-Mail address
            return

        users = users[0]
        if users.check_password(password):
            users.last_login = datetime.utcnow()
            users.save()  # Update the last login of the user
            return users  # Return the given user when the passwords match

    @classmethod
    def create_user(cls, name, password):
        password = password.encode('utf-8')
        password = bcrypt.hashpw(password, bcrypt.gensalt(12))
        user = cls(name=name, password=password)
        user.save()
        return user

    @classmethod
    def user_exists(cls, name):
        user = cls.objects(name__iexact=name)
        if user:
            return user[0]
        return None

    @classmethod
    def get_by_id(cls, id):
        user = cls.objects(id__exact=id)
        if user:
            return user[0]
        return None

    def check_password(self, password):
        """Check if the password match with the password found in the database.

        Args:
            password: (str) the string that need to be compared to the password in the database.

        Returns: 
            True: when the passwords match.
            False: when they don't match.

        Note:
            This task is heavy on the cpu because it hashes the password with bcrypt.
        """
        binary = password.encode(
            'utf-8')  # only binary values can be converted to hashes
        if bcrypt.checkpw(binary, self.password):
            return True
        return False


def login_required(function, denied_function=None):
    """Decorator to check if there is a logged in user.

    Args:
        denied_function: Function that should be called when there is no user.

    Usage:
        @login_required
        async def example(request, user):
            pass
    """

    @wraps(function)
    async def wrapper(request, *args, **kwargs):
        async def access_denied():
            if denied_function:
                return await denied_function(request)
            return response.redirect(APP.config.AUTH_LOGIN_ENDPOINT)

        # Check if session exists.
        session = request.get('session')
        if not request.get('session'):
            return await access_denied()

        # Get session and check if there is a user id.
        user_id = session.get('user_id')
        if not user_id:
            return await access_denied()

        # Check if the id matches with an user in our database.
        user = UserModel.get_by_id(user_id)
        if not user:
            return await access_denied()

        # Add user to the request
        return await function(request, user, *args, **kwargs)
    return wrapper

def required_role(function, roles, denied_function=None):
    """Decorator to check if the user has the required roles

    """
    @wraps(function)
    async def wrapper(request, user, *args, **kwargs):
        async def access_denied():
            if denied_function:
                return await denied_function(request)
            return response.redirect(APP.config.AUTH_LOGIN_ENDPOINT)

        # Transform string into list
        if isinstance(roles, str):
            roles = [roles]

        if not all(item in user.role for item in roles):
            return await access_denied()

        return await function(request, user, *args, **kwargs)
    return wrapper

def login_user(request, user):
    """Login an user with an user object"""
    session = request.get('session')
    if not request.get('session'):
        return False

    session['user_id'] = user.id
    return True


async def login(request, username, password):
    """Login an user with an username and password"""
    user = await UserModel.login(username, password)

    if user is None:
        return False

    login_user(request, user)
    return True


async def logout(request):
    """Delete the user from the session"""
    session = request.get('session')
    if not request.get('session'):
        return

    if session.get('user_id'):
        del session['user_id']

    return response.redirect


async def update_password(user, password, old_password=None):
    if old_password:
        if not user.check_password(old_password):
            return False

    password_bytes = password.encode('utf-8')
    user.password = bcrypt.hashpw(password_bytes, bcrypt.gensalt(12))
    user.save()
    return True


@BLUEPRINT.get('/login')
async def _login_get(request):
    '''Return really simple login page in plain html'''
    return await response.file('./templates/user/login.html')


@BLUEPRINT.post('/login')
async def _login_post(request):
    username = request.form.get('username')
    password = request.form.get('password')

    if password is None or username is None:
        return response.text('password or username is missing.')

    if not await login(request, username, password):
        return response.text('Invalid Username or Password')

    return response.redirect(APP.config.USER_ENDPOINT)


@BLUEPRINT.get('/register')
async def _register_get(request):
    '''Return really simple register page in plain html'''
    return await response.file('./templates/user/register.html')


@BLUEPRINT.route('/logout')
@login_required
async def _logout_route(request, _):
    logout(request)
    return response.redirect(APP.config.AUTH_LOGIN_ENDPOINT)


@BLUEPRINT.post('/register')
async def _register_post(request):
    username = request.form.get('username')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if password is None or username is None or password2 is None:
        return response.text('password or username is missing.')

    if not password == password2:
        return response.text('passwords don\'t match.')

    if not password_check_weak(password):
        return response.text('Your password is too weak.')

    if UserModel.user_exists(username):
        return response.text('Your username is taken')

    user = UserModel.create_user(username, password)

    await login_user(request, user)

    return response.redirect(APP.config.USER_ENDPOINT)
