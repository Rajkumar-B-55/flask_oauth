import logging

from flask import Blueprint
from flask import make_response, jsonify, render_template, request, redirect, session, url_for

from app.models.model import User
from app.services.user_svc import UserService
from app.utils.google_oauth_svc import GoogleSvcAPI
from app.utils.jwt_helper import access_token_generator, refresh_token_generator
from config import config
from app import AppFactory

api_pb = Blueprint('api_bp', __name__, url_prefix='/v1', template_folder='D:/Oauth G&L/app/templates')
# logger
logger = logging.getLogger(__name__)

oauth = AppFactory.oauth
consumer_key = config.LINKEDIN_CLIENT_ID
consumer_secret = config.LINKEDIN_CLIENT_SECRET

request_token_params = {
    'scope': 'openid,profile,email,w_member_social'
}
base_url = 'https://api.linkedin.com/v2/'
request_token_url = None
access_token_method = 'POST'
access_token_url = 'https://www.linkedin.com/oauth/v2/accessToken'
authorize_url = 'https://www.linkedin.com/oauth/v2/authorization'

linkedin_con = oauth.remote_app(

    name='linkedin_oauth',
    consumer_key=consumer_key,
    consumer_secret=consumer_secret,
    request_token_params=request_token_params,
    base_url=base_url,
    request_token_url=request_token_url,
    access_token_method=access_token_method,
    access_token_url=access_token_url,
    authorize_url=authorize_url,
)

linkedin = linkedin_con


@linkedin.tokengetter
def get_linkedin_oauth_token():
    return session.get('linkedin_token')


@api_pb.route('/healthcheck', methods=['GET'])
def healthcheck():
    return '<h1>Health check Success</h1>'


@api_pb.route('/')
def index():
    return redirect('home')


@api_pb.route('/home')
def home():
    return render_template('home.html')


@api_pb.route('/register_template')
def register_template():
    return render_template('signup.html')


@api_pb.route('/register', methods=['POST', 'GET'])
def register():
    try:
        if request.method == "POST":
            if all(key in request.form for key in ['firstname', 'lastname', 'email', 'password']):

                first_name = request.form.get('firstname')
                last_name = request.form.get('lastname')
                email = request.form.get('email')
                password = request.form.get('password')

                user = User.get_by_username(email)
                if not user:
                    new_user = UserService.add_user(first_name, last_name, email, password)
                    logger.info(new_user.email)
                    # return make_response(jsonify({'UserEmail': new_user.email, 'status': "Registered"}))
                    return render_template('register_success.html', email=email)
                else:
                    # return make_response(f' user already exists with email: {email}', 209)
                    return render_template('user_exists.html', email=email)
        else:
            return render_template('signup.html')
    except Exception as e:
        return make_response(jsonify({'error': str(e)}))


@api_pb.route('/login', methods=['POST', 'GET'])
def user_login():
    try:
        if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
            email = request.form.get('email')
            password = request.form.get('password')

            # check user and password check
            user_check = UserService.check_user_exists(email)
            if user_check is not None:
                is_matched = UserService.verify_password(user_check.password, password)

                if is_matched:
                    access_token, refresh_token = access_token_generator(user_check), refresh_token_generator(
                        user_check)
                    resp = {'access_token': access_token, 'refresh_token': refresh_token}
                    payload = jsonify(resp)  # need to check how to use
                    return render_template('user_profile.html', user_data=user_check)
                else:
                    return render_template('user_exists.html', fromlogin=" ")

            else:
                return redirect('home')
    except Exception as e:
        return make_response(jsonify({'error': e.args[0]}))


@api_pb.route("/google_signin")
def google_signin():
    try:
        auth_url = GoogleSvcAPI.login()
        if auth_url is not None:
            return redirect(auth_url)
        return Exception
    except Exception as e:
        return make_response(jsonify({'error': e.args[0]}), 500)


@api_pb.route("/google_signup")
def google_signup():
    try:
        auth_url = GoogleSvcAPI.login()
        if auth_url is not None:
            return redirect(auth_url)
        return Exception
    except Exception as e:
        return make_response(jsonify({'error': e.args[0]}), 500)


@api_pb.route("/google_signup_callback")
def google_callback():
    try:
        code = request.args.get("code")
        response = GoogleSvcAPI.callback(code)

        # session storage
        session["google_id"] = response.get("sub")
        session['first_name'] = response.get('given_name')
        session['family_name'] = response.get('family_name')
        session['email'] = response.get('email')

        email = response['email']
        user_exists = UserService.check_user_exists(email)
        if not user_exists:
            user_dict_google = {
                'first_name': response['given_name'],
                'last_name': response['family_name'],
                'email': response['email']
            }
            new_user = UserService.add_user(user_dict_google['first_name'], user_dict_google['last_name'],
                                            user_dict_google['email'], password='google_admin')
            logger.info(new_user)
            return redirect("/v1/protected_area")
        else:
            return redirect('/v1/protected_area')
    except Exception as e:
        return make_response(jsonify({'error': e.args[0]}), 500)


@api_pb.route('/protected_area')
@GoogleSvcAPI.login_is_required
def protected_area():
    try:
        if session:
            user_data = {
                'first_name': session['first_name'],
                'last_name': session['family_name'],
                'email': session['email']
            }
            return render_template('user_profile.html', user_data=user_data)
        else:
            raise Exception
    except Exception as e:
        return make_response(jsonify({'error': e.args[0]}), 500)


@api_pb.route('/logout')
def logout():
    try:
        if session:
            session.pop('linkedin_token', None)
            session.clear()
            print('session is cleared')
            return redirect('/v1/home')
        else:
            return redirect('/v1/home')
    except Exception as e:
        return make_response(jsonify({'error': e.args[0]}), 500)


@api_pb.route('/linkedin_signin')
def linkedin_signin():
    try:
        if 'linkedin_token' in session:
            session.clear()
            return redirect('/v1/home')
        else:
            return redirect('/v1/linkedin_login')

    except Exception as e:
        return make_response(jsonify({'error': e.args[0]}), 500)


# linkedin
@api_pb.route('/linkedin_signup')
def linkedin_signup():
    try:
        if 'linkedin_token' in session:
            session.clear()
            return redirect('/v1/home')
        else:
            return redirect('/v1/linkedin_login')

    except Exception as e:
        return make_response(jsonify({'error': e.args[0]}), 500)


@api_pb.route('/linkedin_login')
def linkedin_login():
    try:
        return linkedin.authorize(callback=url_for("api_bp.linkedin_authorized", _external=True))
    except Exception as e:
        print(e)
        return make_response(jsonify({'error': e.args[0]}), 500)


@api_pb.route('/linkedin_login/authorized')
def linkedin_authorized():
    try:

        response = linkedin.authorized_response()
        if response is None or response['access_token'] is None:
            return make_response('Access denied: reason={} error={}'.format(
                request.args['error_reason'],
                request.args['error_description']
            ))
        session['linkedin_token'] = (response['access_token'], '')

        me = linkedin.get('userinfo/')

        if me.data['email']:
            email = me.data['email']
            first_name = me.data['given_name']
            last_name = me.data['family_name']
            user_exists = UserService.check_user_exists(email)
            if not user_exists:
                new_user = UserService.add_user(
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    password="linkedin_admin"
                )
                logger.info(new_user)
                return render_template('index.html')
            else:
                user_data = {
                    'first_name': first_name,
                    'last_name': last_name,
                    'email': email,
                }
                return render_template('user_profile.html', user_data=user_data)
    except Exception as e:
        return make_response(jsonify({'error': e.args[0]}), 500)


@api_pb.route('linkedin/logout')
def linkedin_logout():
    try:
        session.pop('linkedin_token', None)
        return redirect(url_for('index'))
    except Exception as e:
        return make_response(jsonify({'error': e.args[0]}), 500)
