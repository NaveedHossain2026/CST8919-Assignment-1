import os
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

load_dotenv()

oauth = OAuth()

auth0 = None  # set by init_auth0() once the Flask app exists


def init_auth0(app):
    """Register the Auth0 OAuth client against the given Flask app.
    Called once from app.py at startup."""
    global auth0
    oauth.init_app(app)
    auth0 = oauth.register(
        "auth0",
        client_id=os.getenv("AUTH0_CLIENT_ID"),
        client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
        client_kwargs={"scope": "openid profile email"},
        server_metadata_url=f'https://{os.getenv("AUTH0_DOMAIN")}/.well-known/openid-configuration',
    )
    return auth0