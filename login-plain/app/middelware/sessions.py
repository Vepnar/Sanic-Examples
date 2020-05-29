# pylint: disable=E0401, W0614, W0401
"""Handle sessions with mongoengine"""
import time
import uuid
from datetime import datetime

from mongoengine import (
    StringField, DateTimeField, DictField, Document
    )

class SessionModel(Document):
    """Store session information."""
    sid = StringField(required=True, unique=True, max_length=32)
    created = DateTimeField(default=datetime.utcnow)
    session_data = DictField(default={})
    meta = {
        'indexes': [{'fields': ['created'], 'expireAfterSeconds': (7 * 24 * 60 * 60)}],
    }


class SessionHandler:
    """Session middleware.

    Handles everything from creating items in the database to settings cookies
    """

    def __init__(
            self,
            app,
            alias: str = None,
            expiry: int = 8 * 60 * 60,
            session_name: str = 'session',
            httponly: bool = True,
            secure: bool = False,
            domain: str = None,

    ):
        self.expiry = expiry
        self.alias = alias
        self.session_name = session_name
        self.httponly = httponly
        self.secure = secure
        self.domain = domain

        if not hasattr(app, "extensions"):
            app.extensions = {}

        app.extensions[self.session_name] = self

        app.request_middleware.appendleft(self.open_sessions)
        app.response_middleware.append(self.save_sessions)

    def _update_session(self, data: dict, sid: str):
        """Update existing session and add new information

        Args: 
            data: (dict) Infomation that should be stored in the database
            sid: (str) Session id where the data should be stored on
        """

        session = SessionModel.objects(sid=sid)
        if not session:
            return
        session = session[0]    
        session.session_data = data
        session.save()

    async def open_sessions(self, request) -> None:
        """Receive session information or set new information"""
        sid, data = request.cookies.get(self.session_name), {}

        if sid:
            data = self._get_session(sid)
            data['_sid'] = sid
        request[self.session_name] = data 

    async def save_sessions(self, request, response) -> None:
        """Store session information into the database"""
        if self.session_name not in request:
            return

        session_data = request[self.session_name]

        # Don't create a session when you don't have anything to store
        if len(session_data.keys()) == 0:
            return
        
        if '_sid' in session_data:
            sid = session_data['_sid']
            if len(session_data.keys()) == 1:
                session_data.pop('_sid')
                self._destroy_session(sid)
                self._destroy_cookie(response)
                return
            if '_renew' in session_data:
                session_data.pop('_renew')
                self._destroy_session(sid)
                sid = self._create_session(session_data)
            self._update_session(session_data, sid)
            self._create_cookie(response, sid)
            return

        if len(session_data.keys()) > 0:
            sid = self._create_session(session_data)
            self._create_cookie(response, sid)

    def _create_session(self, data={}) -> str:
        """Create a new session and return a dict where new information could be stored in

        Args:

        Return:
            (string) Id for the sessions to be stored in
        """

        sid = uuid.uuid4().hex
        session = SessionModel(sid=sid, session_data=data)

        session.save()
        return sid

    def _destroy_session(self, sid: str) -> dict:
        """Delete session from the database"""
        SessionModel.objects(sid=sid).delete()

    def _get_session(self, sid: str):
        """Try to open a session with the given id or create a new one

        Args:
            sid: Session id

        Return: object
            (dict) Data extracted from the session
            (str) Session id
        """

        model = SessionModel.objects(sid=sid)
        if not model:
            return {}
        model = dict(model[0].session_data)
        model.update({'_sid': sid})
        return model

    def _calculate_expire(self) -> datetime:
        """Calculate expire date"""
        expire = time.time() + self.expiry
        return datetime.fromtimestamp(expire)

    def _create_cookie(self, response, sid: str):
        """Create cookie with the given sid"""
        response.cookies[self.session_name] = sid
        response.cookies[self.session_name]['expires'] = self._calculate_expire()
        response.cookies[self.session_name]['max-age'] = self.expiry
        response.cookies[self.session_name]['secure'] = self.secure
        response.cookies[self.session_name]['httponly'] = self.httponly
        if self.domain:
            response.cookies[self.session_name]['domain'] = self.domain

    def _destroy_cookie(self, response) -> None:
        """Destroy the session cookie"""
        del response.cookies[self.session_name]
