import logging

from flask import Blueprint
from flask import make_response, jsonify, render_template, request, redirect, session

from app.models.model import User
from app.services.user_svc import UserService
from app.utils.google_signup import GoogleSvc
from app.utils.new_g import GoogleSvcAPI
from app.utils.jwt_helper import access_token_generator, refresh_token_generator

api_pb = Blueprint('api_bp', __name__, url_prefix='/v1', template_folder='D:/Oauth G&L/app/templates')
# logger
logger = logging.getLogger(__name__)


@api_pb.route('/healthcheck', methods=['GET'])
def healthcheck():
    return '<h1>Health check Success</h1>'


@api_pb.route('/home')
def home():
    return render_template('index.html')


@api_pb.route('/register_template')
def register_template():
    return redirect('register')


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
            return render_template('register.html')
    except Exception as e:
        return make_response(jsonify({'error': str(e)}))


@api_pb.route('/login', methods=['POST'])
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
                    response_payload = {'access_token': access_token, 'refresh_token': refresh_token}
                    jsonify(response_payload)
                    return render_template('user_profile.html', user_data=user_check)
                else:
                    return "Please check your entered password"
            else:
                return redirect('/v1/home')
    except Exception as e:
        return make_response(jsonify({'error': e.args[0]}))


# @api_pb.route('/google_sign_up', methods=['GET'])
# def g_login():
#     try:
#         return redirect(GoogleSvc.requested_uri())
#     except Exception as e:
#         return make_response(jsonify({'error': e.args[0]}), 500)


# @api_pb.route('/verify_google_sign_up', methods=['GET'])
# def verify_g_login():
#     try:
#         info = GoogleSvc.g_signup(request)
#         user = UserService.check_user_exists(info['email'])
#         if user:

#             return render_template('user.html')
#         else:

#             return render_template('register.html')
#     except Exception as e:
#         return make_response(jsonify({'error': e.args[0]}), 500)


#
# @api_pb.route('/google_signup', methods=['GET'])
# def google_signup_index():
#     auth_url = GoogleSvc.generate_auth_url()
#     return auth_url
#
#
# @api_pb.route('/callback')
# def callback():
#     code = request.args.get('code')
#     user_info = GoogleSvc.user_info(code)
#     return render_template('user_info.html', user_info=user_info)


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

        session["google_id"] = response.get("sub")
        session["name"] = response.get("name")
        return redirect("/v1/protected_area")
    except Exception as e:
        return make_response(jsonify({'error': e.args[0]}), 500)


@api_pb.route('/protected_area')
@GoogleSvcAPI.login_is_required
def protected_area():
    return f"Hello {session['name']}! <br/> <a href='/logout'><button>Logout</button></a>"


@api_pb.route('/logout')
def logout():
    session.clear()
    return redirect('v1/home')
