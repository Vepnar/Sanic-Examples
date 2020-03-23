"""All database models are stored in here"""
# pylint: disable=E0401, W0614, W0401, E0602, R0903
import datetime
import bcrypt
from util import sanatize_html
from mongoengine import *


class UserModel(Document):
    """Store session information."""
    email = StringField(required=True, unique=True, max_length=32)
    password = BinaryField(required=True, max_length=60)
    created = DateTimeField(default=datetime.datetime.utcnow)
    last_login = DateTimeField(default=datetime.datetime.utcnow)
    role = StringField(required=True, default='member')

    @classmethod
    def pre_save(cls, sender, document, **kwargs):
        """Hash the plain password"""
        binary = document.password.encode('utf-8')
        document.password = bcrypt.hashpw(binary, bcrypt.gensalt(12))
        document.email = sanitize_html(document.email)

    @classmethod
    def login(cls, email, password):
        """Find a user matching the given E-Mail address and try to login.

        Args:
            email: an email address of an user who has an account on our service.
            password: the password the user has given.

        Returns:
            Returns user object when the user exists.
            Or returns nothing when the user doesn't exist.

        Note:
            This task is heavy on the cpu because it hashes the password with bcrypt.
        """
        users = cls.objects(email=email)
        if not users: # Return no user when there is no matching E-Mail address
            return None
        users = users[0]
        if users.check_password(password):
            users.last_login = datetime.datetime.utcnow()
            users.save() # Update the last login of the user
            return users # Return the given user when the passwords match
        return None # And return nothing when there is no matching user

    @classmethod
    def register(cls, email, password)


    def check_password(self, password):
        """Check if the password match with the password found in the database.

        Args:
            password: (str) the string that need to be compared to the password in the database.

        Returns: 
            True: when the passwords match.
            False: when they don't match.

        Note:
            This task is heavy on the cpu because it hashes the password with bcrypt.
        """
        binary = password.encode('utf-8') # only binary values can be converted to hashes
        if bcrypt.checkpw(binary, self.password):
            return True
        return False

class SessionModel(Document):
    """Store session information."""
    sid = StringField(required=True, unique=True, max_length=32)
    created = DateTimeField(default=datetime.datetime.utcnow)
    session_data = DictField(default={})
    meta = {
        'indexes': [{'fields': ['created'], 'expireAfterSeconds': (7 * 24 * 60 * 60)}],
    }
