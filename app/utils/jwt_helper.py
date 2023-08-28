from flask import request, jsonify, make_response
from functools import wraps
import jwt
import datetime

from app.models.model import User


def access_token_generator(user):
    """
    Access token
    """
    try:
        dt = datetime.datetime.now() + datetime.timedelta(minutes=45)
        token = jwt.encode({
            'user_id': user.pid,
            'email': user.email,
            'exp': dt.utcfromtimestamp(dt.timestamp())
        }, '5beb588a2ace4a41749842930fc1842e', algorithm='HS256')
        return token
    except Exception as e:
        raise e


def refresh_token_generator(user):
    """"
    refresh token
    """
    try:
        dt = datetime.datetime.now() + datetime.timedelta(days=1)
        ref_token = jwt.encode({
            'user_id': user.pid,
            'email': user.email,
            'exp': dt.utcfromtimestamp(dt.timestamp())
        }, '6827502b787742ed5a54fcf785349b07', algorithm="HS256")
        return ref_token
    except Exception as e:
        raise e


def user_auth_decorator(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = None
        if 'authToken' in request.headers:
            token = request.headers['authToken']
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            data = jwt.decode(token, '5beb588a2ace4a41749842930fc1842e', algorithms=['HS256'])
            current_user = User.get_by_id(data['user_id'])
        except jwt.ExpiredSignatureError:
            return make_response('signature expired , login again', 401)
        except jwt.InvalidTokenError:
            return make_response('invalid token', 401)
        return func(current_user)

    return decorated
