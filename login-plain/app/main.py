from sanic import Sanic
from mongoengine import connect

from util.user import initialize

from blueprint.users import BLUEPRINT as users

from sanic_sessions import SessionHandler
from sanic_authenticate import initialize


WEBSERVER = Sanic(__name__,  load_env='S_')


@WEBSERVER.listener('before_server_start')
async def init_webserver(*_):

    # Initialize all database connection
    connect(host=WEBSERVER.config.MONGO_URI)

    # Initialize middelware
    SessionHandler(WEBSERVER)
    initialize(WEBSERVER)
    # Initialize all blueprints
    WEBSERVER.blueprint(users)

if __name__ == "__main__":
    WEBSERVER.run(
        host="0.0.0.0", port=8000, debug=WEBSERVER.config.DEBUG, access_log=False
    )
