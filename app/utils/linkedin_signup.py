from flask import Flask, redirect, url_for, session, request
from flask_oauthlib.client import OAuth

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with your secret key

oauth = OAuth(app)
linkedin = oauth.remote_app(
    'linkedin',
    consumer_key='78mtgl2bd3fqcd',
    consumer_secret='8PIhN5Ald022KlA0',
    request_token_params={
        'scope': 'r_liteprofile r_emailaddress',  # Requested permissions
    },
    base_url='https://api.linkedin.com/v2/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
    authorize_url='https://www.linkedin.com/oauth/v2/authorization',
)


@app.route('/')
def index():
    if 'linkedin_token' in session:
        return 'Logged in as: ' + session['linkedin_token'][0]
    return 'Not logged in.'


@app.route('/login')
def login():
    return linkedin.authorize(callback=url_for('authorized', _external=True))


@app.route('/logout')
def logout():
    session.pop('linkedin_token', None)
    return redirect(url_for('index'))


@app.route('/login/authorized')
def authorized():
    resp = linkedin.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    session['linkedin_token'] = (resp['access_token'], '')
    me = linkedin.get('me', token=resp['access_token'])
    return 'Logged in as: ' + me.data['localizedFirstName']


if __name__ == '__main__':
    app.run(host='localhost', port=5000)
