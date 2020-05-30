# pylint: disable=E0401, W0614, W0401, E0602, R0903
"""Handle users information with mongodb

This will be updated to an asynchronous alternative.
"""


from datetime import datetime
from sanic import Blueprint, response

BLUEPRINT = Blueprint('user', url_prefix='user')


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
