#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

import asyncio
from datetime import datetime

import session
from mongoengine import *

from models import Message
from util import *

from sanic import Sanic, response
from sanic.websocket import WebSocketProtocol
from sanic.exceptions import NotFound

# Setup Sanic webserver
WEBSERVER = Sanic(name='chatbox', load_env='CB_')


@WEBSERVER.listener('before_server_start')
async def init_webserver(app, loop):
    connect(host=WEBSERVER.config.MONGO_URI)
    session.SessionHandler(WEBSERVER)


@WEBSERVER.post('/setnick')
async def set_name(request):
    """Set a nickname to a user in a session"""
    if not request.form.get('nickname'):
        return response.text('Error', status=417, nickname=request['session'].get('nickname'))
    request['session']['nickname'] = request.form.get('nickname')
    return response.redirect('/chatbox')


@WEBSERVER.get('/')
async def index(request):
    """Make it able fo the user to chat"""
    if not request['session'].get('nickname'):
        return await format_html('nickname.html')
    return await format_html('nickname.html', nickname=request['session'].get('nickname'))


@WEBSERVER.get('/chatbox')
async def chatbox(request):
    if not request['session'].get('nickname'):
        return await error_message(403, error_message='Set a nickname first')

    return await format_html(
        'chatbox.html', messages=Message.objects().order_by('posted'), nickname=request['session'].get('nickname')
        )


@WEBSERVER.get('/stats')
async def stats(request):
    """Show statistis on the stats page"""
    messages = Message.objects().count()
    sessions = session.SessionModel.objects().count()
    return await format_html('stats.html', messages=messages, sessions=sessions)


@WEBSERVER.exception(NotFound)
async def error_404(request, exception):
    return await error_message(404, error_message='Page not found', nickname=request['session'].get('nickname'))


@WEBSERVER.websocket('/sendsocket')
async def receive_socket(request, websocket):
    if not request['session'].get('nickname'):
        return
    date = datetime.utcnow()
    while True:
        data = await websocket.recv()
        try:
            print(data)
            # Convert received data to json object
            data = json.loads(data)
            data_type = data.get('type')

            # Process new recieved message
            if data_type == 'msg':
                new_message(request, data)

            # Send new requested files
            elif data_type == 'update':
                date = await send_new_messages(websocket, data, date)

        except ValueError:
            return

if __name__ == "__main__":
    WEBSERVER.static('/static', './static')
    WEBSERVER.run(
        host="0.0.0.0", port=8000, debug=True, access_log=False, protocol=WebSocketProtocol
    )
