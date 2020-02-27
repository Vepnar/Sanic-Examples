#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=E0401, W0614, W0401
"""Main sanic landing page"""
from users import BLUEPRINT as Users
from util import format_html

from sanic import Sanic, response
from sanic.exceptions import NotFound
from mongoengine import connect
import session


# Setup Sanic webserver
WEBSERVER = Sanic(name='login', load_env='CB_')

@WEBSERVER.listener('before_server_start')
async def init_webserver(*_):
    """Initialisatie webserver and sessions"""
    connect(host=WEBSERVER.config.MONGO_URI)
    session.SessionHandler(WEBSERVER)

@WEBSERVER.exception(NotFound)
async def error_404(request, _):
    """Process not found exceptions"""
    return await format_html('error.html', error_code=404, request=request)

@WEBSERVER.get('/')
async def index(_):
    """There is no index page so we redirect the users to the user page"""
    return response.redirect('/users/')

if __name__ == "__main__":
    WEBSERVER.static('/static', './static')
    WEBSERVER.blueprint(Users)
    WEBSERVER.run(
        host="0.0.0.0", port=8000, debug=True, access_log=False
    )
