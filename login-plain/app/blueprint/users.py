# pylint: disable=E0401, W0614, W0401, E0602, R0903
"""Handle users information with mongodb"""
import bcrypt
from mongoengine import *
from sanic_auth import Auth
from datetime import datetime
from sanic import Blueprint, response

from util.user_util import password_check_weak

BLUEPRINT = Blueprint('user', url_prefix='user')
AUTH = None

def Userhandler(app):
    global AUTH
    AUTH = Auth(app)

class UserModel(Document):
    """Basic user database model with roles"""
    username = StringField(required=True, unique=True, max_length=32)
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
        users = cls.objects(username=username)
        if not users:  # Return no user when there is no matching E-Mail address
            return

        users = users[0]
        if users.check_password(password):
            users.last_login = datetime.utcnow()
            users.save()  # Update the last login of the user
            return users  # Return the given user when the passwords match

    @classmethod
    def create_user(cls, username, password):
        password = password.encode('utf-8')
        password = bcrypt.hashpw(password, bcrypt.gensalt(12))
        user = cls(username=username, password=password)
        user.save()
        return user

    @classmethod
    def user_exists(cls, username):
        user =  cls.objects(username__iexact=username) is None
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
    AUTH.login_user(request, user)


@BLUEPRINT.get('/register')
async def register_get(request):
    '''Return really simple register page in plain html'''
    return await response.file('./templates/user/register.html')


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

    if not UserModel.user_exists(username):
        return response.text('Your username is taken')

    user = UserModel.create_user(username, password)

    AUTH.login_user(request, user)

    response.redirect('/')
