import os
import uuid
from flask import Flask, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

load_dotenv()

# Use SESSION_SECRET from env, or generate a random one if not present
secret_key = os.getenv("SESSION_SECRET")
if not secret_key:
    secret_key = str(uuid.uuid4())

app = Flask(__name__)
app.secret_key = secret_key

app.config.update(
    SESSION_COOKIE_NAME='oidc_session',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # Set to True if using HTTPS
    SESSION_COOKIE_SAMESITE='Lax',  # Adjust as needed
    PREFERRED_URL_SCHEME='https'  # Ensure URLs are generated as HTTPS
)

oauth = OAuth(app)
client = oauth.register(
    name='oidc',
    client_id=os.getenv("CLIENT_ID"),
    client_secret=os.getenv("CLIENT_SECRET"),
    server_metadata_url=os.getenv('SERVER_METADATA_URL'),
    client_kwargs={
        'scope': 'openid profile email',
        'verify': False
    }
)

@app.route('/')
def homepage():
    user = dict(session).get('user')
    if user:
        return f'Hello, {user["name"]}! You may close this page or <a href="/logout">Logout</a>'
    return '<a href="/login">Login</a>'

@app.route('/login')
def login():
    redirect_uri = url_for('auth_callback', _external=True)
    return client.authorize_redirect(redirect_uri)

@app.route('/authorization-code/callback')
def auth_callback():
    try:
        token = client.authorize_access_token()
        nonce = session.pop('nonce', None)
        userinfo = client.parse_id_token(token, nonce=nonce)
        if not userinfo:
            return 'Authentication failed', 401
        session['user'] = userinfo
        return redirect('/')
    except Exception as e:
        return f'An error occurred: {str(e)}', 500

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)