import os
import uuid
import requests
from flask import Flask, redirect, url_for, session, request, render_template
from authlib.integrations.flask_client import OAuth
from authlib.jose import jwt
import time
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
        'verify': True
    }
)

@app.route('/trigger', methods=['GET'])
def trigger():
    tid = request.args.get('tid')
    if tid:
        session['telegram_id'] = tid
        return render_template('login.html')
    return render_template('error.html', error_message="Telegram ID parameter is missing", show_home_button=False), 400

@app.route('/')
def homepage():
    tid = dict(session).get('telegram_id')
    if tid:
        user = dict(session).get('user')
        if user:
            try:
                payload = {
                    "iss": "smrutirbot",
                    "tid": tid,
                    "user": user,
                    "iat": int(time.time()),
                    "exp": int(time.time()) + 300
                }
                header = {"alg": "HS256"}
                token = jwt.encode(header, payload, os.getenv("JWT_SECRET"))

                headers = {"Authorization": f"Bearer {token.decode() if isinstance(token,bytes) else token}"}

                response = requests.post(os.getenv("SMRUTIRBOT_AUTH_URL"), json=payload, headers=headers)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                return render_template('error.html', error_message=f"An error occurred while sending data: {e}", show_home_button=True), 500
            return render_template('home.html', user=user)
        return render_template('login.html')
    return render_template('error.html', error_message="Telegram ID parameter is missing", show_home_button=False), 400

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
            return render_template('error.html', error_message="Authentication failed", show_home_button=False), 401
        session['user'] = userinfo
        return redirect('/')
    except Exception as e:
        return render_template('error.html', error_message=f"An error occurred: {str(e)}", show_home_button=True), 500

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)