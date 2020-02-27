# pylint: disable=E0401, W0614, W0401
"""Process user accounts using sessions and mongoengine"""
from sanic import response, Blueprint

import session
from util import *

BLUEPRINT = Blueprint('users', url_prefix='/users')


@BLUEPRINT.get('/register')
async def register(request):
    """Show the register page when not logged in."""
    if is_logged_in(request):
        return response.redirect('profile')
    return await format_html('register.html')


@BLUEPRINT.get('/')
async def index(request):
    """Redirect based on the current state."""
    if is_logged_in(request):
        return response.redirect('/users/profile')
    return response.redirect('/users/login')


@BLUEPRINT.get('/profile')
async def profile(request):
    """Show profile when the user is logged in."""
    if is_logged_in(request):
        return await format_html('profile.html', request=request)
    else:
        return response.redirect('login')


@BLUEPRINT.get('/logout')
async def logout(request):
    """Log the user out when it's logged in"""
    if is_logged_in(request):
        del request['session']['user_id']
    return response.redirect('login')


@BLUEPRINT.get('/test')
async def test(request):
    """Just for testing"""
    sessions = session.SessionModel.objects.count()
    users = UserModel.objects.count()
    does_have_session = request.get('session')
    user_id = request['session'].get('user_id')
    error = f'''
    Amount of session: {sessions}<br>
    Amount of users: {users}<br>
    session: {does_have_session}<br>
    user_id: {user_id}'''

    return await format_html(
        'error.html', error_code=200, error_message=error, request=request
    )


@BLUEPRINT.get('/login')
async def login(request):
    """Show the login page when not logged in"""
    if is_logged_in(request):
        return response.redirect('profile')
    return await format_html('login.html')


@BLUEPRINT.post('/register')
async def register_post(request):
    """Processes post requests.

    This will check if the form contains all information.
    After that it will create a new user and store the id in the sessions.

    Request args:
        email: a not registed email-address.
        pwd-1: a strong password with at least 6 characters 1 capital and 1 digit.
        pwd-2: same as string as pwd-1.
        accept: has to be on.

    Exceptions:
        - Email is not an email.
        - passwords is not valid.
        - passwords do not match.
        - tos not accepted.
        -
    """
    if is_logged_in(request):
        return response.redirect('profile')

    required = ['email', 'pwd-1', 'pwd-2', 'accept']
    if not all(item in request.form for item in required):
        return await format_html(
            'register.html', error_message='Please accept our TOS', request=request
        )

    email = request.form.get('email', '').lower()
    password = request.form.get('pwd-1')
    password2 = request.form.get('pwd-2')
    accept = request.form.get('accept')

    message = can_register_user(email, password, password2, accept)
    if message is not None:
        return await format_html(
            'register.html', error_message=message, email=email
        )

    hashed_password = hash_password(password)
    new_user = UserModel(email=email, password=hashed_password)
    new_user.save()

    request['session']['user_id'] = new_user.id
    return response.redirect('profile')


@BLUEPRINT.post('/login')
async def login_post(request):
    """Process login post requests.

    This will check if the login form contains all required information.
    After that it will try to login the user, and give the user a session.

    Request args:
        email: An email from an account that's registerd.
        password: the password for the registerd account.

    Exceptions:
        - Account does not exist.
        - Password is invalid.
        - Not all fields are entered.
        - Already logged in
    """
    if is_logged_in(request):
        return response.redirect('profile')

    required = ['email', 'pwd']
    if not all(item in request.form for item in required):
        return await format_html('login.html', error_message='Please enter all fields')

    email = request.form.get('email')
    password = request.form.get('pwd')
    user = attempt_login(email, password)

    if not user:
        return await format_html(
            'login.html', error_message='Password incorrect', email=email
        )

    request['session']['user_id'] = user.id
    return response.redirect('profile')
