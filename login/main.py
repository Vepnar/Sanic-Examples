#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from util import format_html
from users import BLUEPRINT as Users

from sanic import Sanic, response
from sanic.exceptions import NotFound
from mongoengine import connect
import session


# Setup Sanic webserver
WEBSERVER = Sanic(name='login', load_env='CB_')

@WEBSERVER.listener('before_server_start')
async def init_webserver(app, loop):
    connect(host=WEBSERVER.config.MONGO_URI)
    session.SessionHandler(WEBSERVER)

@WEBSERVER.exception(NotFound)
async def error_404(request, exception):
    return await format_html('error.html', error_code=404)

@WEBSERVER.get('/')
async def index(request):
    return await format_html('index.html')

if __name__ == "__main__":
    WEBSERVER.static('/static', './static')
    WEBSERVER.blueprint(Users)
    WEBSERVER.run(
        host="0.0.0.0", port=8000, debug=True, access_log=False
    )
