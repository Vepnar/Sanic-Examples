# pylint: disable=E0401, W0614, W0401, E0602, R0903
"""Handle users information with mongodb"""
import bcrypt
from mongoengine import *
from functools import wraps
from datetime import datetime
from sanic import Blueprint, response

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
    role = StringField(required=True, default='member')

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
        user = cls.objects(id__exact=name)
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

def login_required(func, denied_function=None):
    """Decorator to check if there is a logged in user.

    Args:
        denied_function: Function that should be called when there is no user.

    Usage:
        @login_required
        async def example(request):
            pass
    """

    def wrapper(func):
        @wraps(func)
        async def wrapped(request, *args, **kwargs):
            async def access_denied():
                if denied_function:
                    return await denied_function(request)
                return response.redirect(APP.config.AUTH_LOGIN_ENDPOINT)

            # Check if session exists.
            session = request.get('session')
            if not request.get('session'):
                await access_denied()

            # Get session and check if there is a user id.
            user_id = session.get('user_id')
            if not user_id:
                await access_denied()

            # Check if the id matches with an user in our database.
            user = UserModel.get_by_id(user_id)
            if not user:
                await access_denied()

            request['user'] = user
            func(request, *args, **kwargs)
            
        return wrapped
    return wrapper


@BLUEPRINT.get('/login')
async def login_get(request):
    '''Return really simple login page in plain html'''
    return await response.file('./templates/user/login.html')


@BLUEPRINT.post('/login')
async def login_post(request):
    username = request.form.get('username')
    password = request.form.get('password')

    if password is None or username is None:
        return response.text('password or username is missing.')

    user = UserModel.login(username, password)

    if user is None:
        return response.text('Invalid Username or Password')

    #TODO LOGIN AUTH

    return response.redirect(APP.config.USER_ENDPOINT)


@BLUEPRINT.get('/register')
async def register_get(request):
    '''Return really simple register page in plain html'''
    return await response.file('./templates/user/register.html')


@BLUEPRINT.route('/logout')
@AUTH.login_required
async def logout_route(request):
    # TODO LOGOUT AUTH
    return response.redirect(response.redirect(APP.config.AUTH_LOGIN_ENDPOINT))


@BLUEPRINT.post('/register')
async def register_post(request):
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

    # LOGIN AUTH

    return response.redirect(APP.config.USER_ENDPOINT)
