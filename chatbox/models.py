from mongoengine import *
from datetime import datetime

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