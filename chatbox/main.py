#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import json
import jinja2
import asyncio
from mongoengine import *
from datetime import datetime
from sanic import Sanic, response
import engine_session
from sanic.websocket import WebSocketProtocol

# Setup Saninc webserver
WEBSERVER = Sanic(name='chatbox', load_env='CB_')
ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader('./templates'),
    enable_async=True
)


class Message(Document):
    """Example message document"""
    message = StringField(required=True, max_length=256)
    posted = DateTimeField(default=datetime.utcnow)
    sender = StringField(required=True, max_length=16)
    meta = {
        'indexes': [
            {'fields': ['posted'],
            'expireAfterSeconds': 6000}
        ]
    }


async def format_html(html_file, **kwargs):
    """Format a html file with just the name and kwargs"""
    template = ENV.get_template(html_file)
    formatted_template = await template.render_async(**kwargs)
    return response.html(formatted_template)


async def error_message(error_code, error_message=None):
    return await format_html('error.html', error_code=error_code, error_message=error_message)


@WEBSERVER.listener('before_server_start')
async def init_webserver(app, loop):
    connect(host=WEBSERVER.config.MONGO_URI)


@WEBSERVER.post('/setnick')
async def set_name(request):
    """Set a nickname to a user in a session"""
    if not request.form.get('nickname'):
        return response.text('Error', status=417)
    request['session']['nickname'] = request.form.get('nickname')
    return response.redirect('/chatbox')


@WEBSERVER.get('/')
async def index(request):
    """Make it able fo the user to chat"""
    if not request['session'].get('nickname'):
        return await format_html('nickname.html')
    return await format_html('nickname.html')


@WEBSERVER.get('/chatbox')
async def chatbox(request):
    if not request['session'].get('nickname'):
        return await error_message(403, error_message='Set a nickname first')

    return await format_html('chatbox.html', messages=Message.objects().order_by('posted'))


@WEBSERVER.get('/stats')
async def stats(request):
    messages = Message.objects().count()
    sessions = engine_session.SessionModel.objects().count()
    return await format_html('stats.html', messages=messages,sessions=sessions)


@WEBSERVER.websocket('/receivesocket')
async def receive_socket(request, websocket):
    # if not request['session'].get('nickname'):
    #     return

    while True:
        await asyncio.sleep(0.5)
        msg = Message.objects(posted__gte=date)
        websocket.send(msg)

def make_html_safe(html_code):
    return re.sub(r'\<.*?>', '', html_code)

@WEBSERVER.websocket('/sendsocket')
async def receive_socket(request, websocket):
    if not request['session'].get('nickname'):
        return
    date = datetime.utcnow()
    while True:
        data = await websocket.recv()
        try:
            data = json.loads(data)
            if data.get('type') == 'msg':
                if not data.get('msg'):
                    continue
                message = make_html_safe(data.get('msg'))
                Message(sender=request['session']['nickname'], message=message).save()
                continue
                
            new_messages = Message.objects(posted__gte=date)
            if new_messages:
                formatted_messages = []
                for message in new_messages:
                    new_msg = {
                        'posted' : message.posted.strftime('%d %B %H:%M'),
                        'sender' : message.sender,
                        'message' : message.message
                    }
                    formatted_messages.append(new_msg)
                date = datetime.utcnow()
                await websocket.send(json.dumps(formatted_messages))
                continue
            await websocket.send('[]')
        except ValueError:
            return
        
        

if __name__ == "__main__":
    engine_session.SessionHandler(WEBSERVER)
    WEBSERVER.run(
        host="0.0.0.0", port=8000, debug=True, access_log=False, protocol=WebSocketProtocol)