import time
import uuid
from mongoengine import *
from datetime import datetime


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

    Args:
    """

    def __init__(
        self,
        app,
        alias: str = None,
        expiry: int = 7 * 24 * 60 * 60,
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

    async def open_sessions(self, request) -> None:
        """Receive session infomration or set new information"""
        sid, data = request.cookies.get(self.session_name), {}

        if sid:
            data, sid = self._get_session(sid)
            if sid:
                data['_sid'] = sid
        request[self.session_name] = data

    async def save_sessions(self, request, response) -> None:
        """Store session information into the database"""
        if self.session_name not in request:
            return
            
        session_data = request[self.session_name]

        if '_sid' in request[self.session_name]:
            self._destroy_session(request[self.session_name]['_sid'])
            del session_data['_sid']
            if not len(request[self.session_name].keys()):
                self._destroy_cookie(response)
                return

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

        # Set meta informaton for example alias and expire date
        # meta = {
        #     'indexes': [{'fields': ['created'], 'expireAfterSeconds': 600}]
        # }
        # if not self.alias:
        #     meta.update({'db_alias': self.alias})
        # session.meta = meta
        session.save()
        return sid

    def _destroy_session(self, sid: str) -> None:
        SessionModel.objects(sid=sid).delete()

    def _get_session(self, sid: str) -> (dict, str):
        """Try to open a session with the given id or create a new one

        Args:
            sid: Session id

        Return: object
            (dict) Data extracted from the session
            (str) Session id
        """

        model = SessionModel.objects(sid=sid)
        if not model:
            return {}, None
        return dict(model[0].session_data), sid

    def _calculate_expire(self):
        expire = time.time() + self.expiry
        return datetime.fromtimestamp(expire)

    def _create_cookie(self, response, sid):
        response.cookies[self.session_name] = sid
        response.cookies[self.session_name]['expires'] = self._calculate_expire()
        response.cookies[self.session_name]['max-age'] = self.expiry

        if self.domain:
            response.cookies[self.session_name]['domain'] = self.domain
        response.cookies[self.session_name]['secure'] = self.secure
        response.cookies[self.session_name]['httponly'] = self.httponly

    def _destroy_cookie(self, response) -> None:
        """Destroy the session cookie"""
        del response.cookies[self.session_name]
