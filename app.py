import json
import logging
import os
import sys
from urllib.parse import quote_plus, urlencode

from flask import Flask, redirect, render_template, request, session, url_for
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

from auth import init_auth0

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('AUTH0_SECRET')


app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

auth0 = init_auth0(app)

# ---------------------------------------------------------------------------
# Structured logging (Assignment 1) - stdout -> AppServiceConsoleLogs in Azure
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(message)s")
logger = logging.getLogger("SecurityLogger")


def log_event(event_type, level="info", **fields):
    payload = {"event": event_type, **fields}
    line = json.dumps(payload, default=str)
    if level == "warning":
        logger.warning(line)
    else:
        logger.info(line)


def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def get_user():
    """Mirrors the shape of the old auth0-server-python `get_user()` call:
    returns the userinfo dict if logged in, else None."""
    return session.get("user")


@app.route('/')
def index():
    """Home page - shows login button or user profile"""
    user = get_user()
    return render_template('index.html', user=user)


@app.route('/login')
def login():
    """Redirect to Auth0 login"""
    return auth0.authorize_redirect(redirect_uri=url_for('callback', _external=True))


@app.route('/callback')
def callback():
    """Handle Auth0 callback after login"""
    try:
        token = auth0.authorize_access_token()
        userinfo = token.get('userinfo', {}) if token else {}
        session['user'] = userinfo

        log_event(
            "login_success",
            user_id=userinfo.get("sub"),
            email=userinfo.get("email"),
            ip=client_ip(),
        )

        return redirect(url_for('index'))
    except Exception as e:
        log_event(
            "login_error",
            level="warning",
            error=str(e),
            ip=client_ip(),
        )
        return f"Authentication error: {str(e)}", 400


@app.route('/profile')
def profile():
    """Protected route - shows user profile"""
    user = get_user()

    if not user:
        log_event(
            "unauthorized_attempt",
            level="warning",
            path=request.path,
            method=request.method,
            ip=client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return redirect(url_for('login'))

    return render_template('profile.html', user=user)


@app.route('/protected')
def protected():
    """Protected page - only authenticated users can access.

    Every visit is logged as a `protected_access` event (user_id, email,
    ip). The KQL query in README.md aggregates these events per user over
    a 15-minute window to detect excessive access to this sensitive route.
    """
    user = get_user()

    if not user:
        log_event(
            "unauthorized_attempt",
            level="warning",
            path=request.path,
            method=request.method,
            ip=client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return redirect(url_for('login'))

    log_event(
        "protected_access",
        user_id=user.get("sub"),
        email=user.get("email"),
        ip=client_ip(),
    )

    return render_template('protected.html', user=user)


@app.route('/logout')
def logout():
    """Logout and redirect to Auth0 logout"""
    user = get_user()
    log_event(
        "logout",
        user_id=(user or {}).get("sub"),
        email=(user or {}).get("email"),
    )

    session.clear()
    return redirect(
        "https://"
        + os.getenv("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("index", _external=True),
                "client_id": os.getenv("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


if __name__ == '__main__':
    app.run(debug=True, port=5000)
