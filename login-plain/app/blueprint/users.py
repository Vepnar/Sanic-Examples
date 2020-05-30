# pylint: disable=E0401, W0614, W0401, E0602, R0903
"""Handle users information with mongodb

This will be updated to an asynchronous alternative.
"""


from datetime import datetime
from sanic import Blueprint, response

import util.user as u

BLUEPRINT = Blueprint('user', url_prefix='user')

@BLUEPRINT.get('/')
@u.get_user
async def index(request, user):
    if user is not None:
        return response.text(user.name)
    return response.text(request.get('session'))


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

    if not await u.authenticate(request, username, password):
        return response.text('Invalid username or password')

    return response.redirect('/user/')


@BLUEPRINT.get('/register')
async def _register_get(request):
    '''Return really simple register page in plain html'''
    return await response.file('./templates/user/register.html')


@BLUEPRINT.route('/logout')
@u.login_required
async def _logout_route(request, _):
    await u.logout(request)
    return response.redirect('/users/')


@BLUEPRINT.post('/register')
async def _register_post(request):
    username = request.form.get('username')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if password is None or username is None or password2 is None:
        return response.text('password or username is missing.')

    if not password == password2:
        return response.text('passwords don\'t match.')

    if not u.password_check_weak(password):
        return response.text('Your password is too weak.')

    if await u.user_exists(username):
        return response.text('Your username is taken')

    user = await u.create_user(username, password)

    await u.login(request, user)

    return response.redirect('/user/')
