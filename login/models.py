"""All database models are stored in here"""
# pylint: disable=E0401, W0614, W0401, E0602, R0903
import datetime
from mongoengine import *


class UserModel(Document):
    """Store session information."""
    email = StringField(required=True, unique=True, max_length=32)
    password = BinaryField(required=True, max_length=60)
    created = DateTimeField(default=datetime.datetime.utcnow)
    last_login = DateTimeField(default=datetime.datetime.utcnow)
    role = StringField(required=True, default='member')


class SessionModel(Document):
    """Store session information."""
    sid = StringField(required=True, unique=True, max_length=32)
    created = DateTimeField(default=datetime.datetime.utcnow)
    session_data = DictField(default={})
    meta = {
        'indexes': [{'fields': ['created'], 'expireAfterSeconds': (7 * 24 * 60 * 60)}],
    }
