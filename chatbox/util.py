# -*- coding: utf-8 -*-
"""Perform simple utility tasks we dont wan't to show up in the main file"""

import re
import json
import asyncio
import jinja2

from models import Message
from sanic import response
from datetime import datetime


ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader('./templates'),
    enable_async=True
)


async def error_message(error_code: int, error_message=None):
    """Format error messages with just one function.

    Args:
        error_code: (int) http error code to show up to the browser.
        error_message: (str) message to show up in the browser.

    Return:
        HTTPResponse
    """
    return await format_html('error.html', error_code=error_code, error_message=error_message)


def new_message(request, message: str) -> None:
    """Processes new recieved messages and add them to the database

    Args:
        Message: (str) unparsed message that should be added to the database

    Return:
        None
    """
    if not message.get('msg'):
        return
    message = re.sub(r'\<.*?>', '', message.get('msg')).strip()
    if message:
        Message(sender=request['session']['nickname'], message=message).save()


def rebuild_messages(messages: list) -> str:
    """Make the messages usable for Jinja

    Args:
        message: (list) list of Message objects

    Return:
        Messages in a json string
    """
    formatted_messages = []
    for message in messages:
        new_msg = {
            'posted': message.posted.strftime('%d %B %H:%M'),
            'sender': message.sender,
            'message': message.message
        }
        formatted_messages.append(new_msg)
    return json.dumps(formatted_messages)


async def send_new_messages(websocket, data: dict, date: datetime) -> datetime:
    new_messages = Message.objects(posted__gte=date)
    if new_messages:
        formatted_messages = rebuild_messages(new_messages)
        await websocket.send(formatted_messages)
    else:
        await websocket.send('[]')
    return datetime.utcnow()


async def format_html(html_file: str, **kwargs):
    """Format a html file with just the name and kwargs"""
    template = ENV.get_template(html_file)
    formatted_template = await template.render_async(**kwargs)
    return response.html(formatted_template)
