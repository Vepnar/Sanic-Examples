"""User handler with mongoengine

TODO: replace mongoengine with something async
"""
import bcrypt

from sanic import response
from functools import wraps
from datetime import datetime
from mongoengine import (
    Document, StringField, BinaryField, DateTimeField, ListField, ReferenceField, PULL
)

APP = None

BAD_PASSWORDS = [
    'pass',
    '123',
    'abc',
    'qwerty',
    'dragon',
    '69',
    '420',
    '321'
]


def initialize(app):
    global APP
    APP = app


class UserModel(Document):
    """Basic user database model with roles"""
    name = StringField(required=True, unique=True, max_length=32)
    password = BinaryField(required=True, max_length=60)
    created = DateTimeField(default=datetime.utcnow)
    last_login = DateTimeField(default=datetime.utcnow)
    role = ListField(StringField())

async def login(request, user):
    """Login an user with an user object"""
    session = request.get('session')
    if request.get('session') is None:
        return False

    session['user_id'] = user.id
    return True

async def check_password(user, password):
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
    if bcrypt.checkpw(binary, user.password):
        return True
    return False

async def authenticate(request, username, password):
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
    users = UserModel.objects(name__exact=username)
    if not users:  # Return no user when there is no matching username address
        return
    print("NOTHING FOUND")

    users = users[0]
    if await check_password(users, password):
        users.last_login = datetime.utcnow()
        users.save()  # Update the last login of the user
        await login(request, users)
        return users  # Return the given user when the passwords match


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


async def add_role(user, roles):
    if isinstance(roles, str):
        roles = [roles]

    for role in roles:
        user.role.append(role) if role not in user.role else role
    user.save()


async def remove_role(user, roles):
    """Remove on or more roles from a given user.

    Args:
        user: the user we should remove the roles from.
        roles: A string or list filled with roles that should be removed.
    """

    if isinstance(roles, str):
        roles = [roles]

    for role in roles:
        user.role.remove(role) if role in user.role else role
    user.save()


async def create_user(username, password):
    """Create an user if the username isn't taken yet

    Args:
        username: a not used username.
        password: a non hashed version of the password.

    Returns:
        None: when the username exists.
        User: when the username doesn't exist.

    """

    password = password.encode('utf-8')
    password = bcrypt.hashpw(password, bcrypt.gensalt(12))
    user = UserModel(name=username, password=password)
    user.save()
    return user


async def user_exists(name):
    """Checks if the username exists.

    Args:
        username: a username you want to look up.

    Returns:
        None: when there is no user.
        User: when there is an user found.

    """
    user = UserModel.objects(name__iexact=name)
    if user:
        return user[0]
    return None


async def get_by_id(id):
    """Get user by ID.

    Args:
        id: mongodb object id.

    Return:
        user: usermodel from the database.
        None: when the id is invalid or when there is nothing found.
    """
    try:
        user = UserModel.objects(id__exact=id)
        if user:
            return user[0]
    except:
        pass


def password_check_weak(password):
    """Weak password checker:

    Only checks if the password is longer than 6 characters and doesn't container any spaces.

    Returns true when the password is strong and false when it isn't

    """
    return len(password) > 6 and not password.isspace()


def password_check_middel(password):
    """Middel password checker.
    - Should contain everthing from before.
    - Should also contain no atleast 1 capital letter and 1 lowercase letter.
    - Should contain atleast 1 letter and 1 digit.

    Returns true when the password is strong and false when it isn't
    """
    if not password_check_weak(password):
        return False

    if password.lower() == password or password.upper() == password or password.isalpha() or password.isdigit():
        return False
    return True


def password_check_strong(password):
    """Strong password checker.
    - Should contain everthing from before.
    - Should contain 1 non letter / digit.   

    Returns true when the password is strong and false when it isn't
    """
    if not password_check_middel(password):
        return False

    if password.isalnum():
        return False
    return True


def password_check_extra_strong(password):
    """Extra strong password checker.
    - Should contain everthing from before.
    - Should contain more than 5 unique characters
    - Should contain more than 11 characters
    - Shouldn't be on the password blacklist

    Returns true when the password is strong and false when it isn't
    """
    if not password_check_strong(password):
        return False

    # Password needs to be longer than 11 characters.
    if len(password) < 11:
        return False

    # Convert password to lowercase
    password = password.lower()

    # Passwords must contain more than 5 unique characters.
    unique = []
    for char in password[::]:
        if char not in unique:
            unique.append(char)

    if len(unique) < 5:
        return False

    # Password should not be blacklisted
    for bad_pass in BAD_PASSWORDS:
        if bad_pass in password:
            return False

    return True

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
        print(request.get('session'))
        session = request.get('session')
        if not request.get('session'):
            return await access_denied()

        

        # Get session and check if there is a user id.
        user_id = session.get('user_id')
        if not user_id:
            return await access_denied()

        # Check if the id matches with an user in our database.
        user = await  get_by_id(user_id)
        if not user:
            return await access_denied()

        # Add user to the request
        return await function(request, user, *args, **kwargs)
    return wrapper

def get_user(function):
    """Decorator to add the user to the arguments of the called function

    Usage:
        @get_user
        async def example(request, user):
            pass
    """

    @wraps(function)
    async def wrapper(request, *args, **kwargs):
        async def call_function(user=None):
            return await function(request, user, *args, **kwargs)

        # Check if session exists.
        session = request.get('session')
        if not request.get('session'):
            return await call_function()

        # Get session and check if there is a user id.
        user_id = session.get('user_id')
        if not user_id:
            return await call_function()

        # Check if the id matches with an user in our database.
        user = await get_by_id(user_id)
        if not user:
            return await call_function()

        # Add user to the request
        return await call_function(user=user)
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
