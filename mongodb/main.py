#!/usr/bin/env python3
"""
Simple Sanic example that uses mongodb to store messages
Author: Arjan de Haan (Vepnar)
Version: 0.1
Last edited: 06-02-2020
"""

from sanic import Sanic, response
from datetime import datetime
from mongoengine import *

APP = Sanic(name='MongoDB example')

class Message(Document):
    """Example message document"""
    message = StringField(required=True,max_length=256)
    posted = DateTimeField(default=datetime.utcnow)

@APP.route('/')
async def message_list(request):
    """Show all the messages added to the database and show an option to add more"""
    messages_objects = Message.objects().order_by('posted')
    html = ''
    for message in messages_objects:
        time_string = message.posted.strftime('%H:%M')
        html+=f'<a href="{message.id}/del/">X</a><b>{time_string}</b> <span>{message.message}</span><br>'

    html+='<form action="/add" method="post"><input type="text" name="message"><input type="submit"></form>'
    return response.html(html)

@APP.route('<id>/del')
async def delete_message(request, id: int):
    """Delete a message"""
    Message.objects().filter(id=id).delete()
    return response.redirect('/')

@APP.post('/add')
async def add(request):
    """Add a new message to the database"""
    if not request.form.get('message', default=None):
        return response.text('Error', status=417)
    Message(message=request.form.get('message')).save()
    return response.redirect('/')

if __name__ == '__main__':
    connect('test', host='mongo', port=27017)
    APP.run(host='0.0.0.0', port=8000)
