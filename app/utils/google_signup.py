import json

import requests
from flask import request
from oauthlib import oauth2

from config import config


class GoogleSvc:
    CLIENT_ID = config.GOOGLE_CLIENT_ID
    CLIENT_SECRET = config.GOOGLE_CLIENT_SECRET
    REDIRECT_URI = config.GOOGLE_REDIRECT_URI
    SCOPE = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email',
             'openid']

    CLIENT = oauth2.WebApplicationClient(client_id=CLIENT_ID)

    DATA = {
        'response_type': "code",  # this tells the auth server that we are invoking authorization workflow
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPE,
        'client_id': CLIENT_ID,  # client ID from https://console.developers.google.com/apis/credentials
        'prompt': 'consent'}

    URL_DICT = {
        'google_oauth': 'https://accounts.google.com/o/oauth2/v2/auth',  # Google OAuth URI
        'token_gen': 'https://oauth2.googleapis.com/token',  # URI to generate token to access Google API
        'get_user_info': 'https://www.googleapis.com/oauth2/v3/userinfo'  # URI to get the user info
    }

    @classmethod
    def generate_auth_url(cls):
        auth_url, _, _ = cls.CLIENT.prepare_authorization_request(
            'https://accounts.google.com/o/oauth2/auth',
            redirect_url=cls.REDIRECT_URI,
            scope=[cls.SCOPE],
        )
        return auth_url

    @classmethod
    def user_info(cls, code):
        token_url, _ = cls.CLIENT.prepare_token_request(
            'https://oauth2.googleapis.com/token',
            authorization_response=request.url,
            redirect_url=cls.REDIRECT_URI,
            code=code,
        )
        token_response = requests.post(
            token_url,
            auth=(cls.CLIENT_ID, cls.CLIENT_SECRET)
        )
        cls.CLIENT.parse_request_body_response(token_response.text)
        uri, headers, _ = cls.CLIENT.add_token('https://www.googleapis.com/oauth2/v3/userinfo')
        user_info_response = requests.get(uri, headers=headers)
        return user_info_response.json()


    # old code

    @classmethod
    def requested_uri(cls):
        return cls.CLIENT.prepare_request_uri(
            uri=cls.URL_DICT['google_oauth'],
            redirect_uri=cls.DATA['redirect_uri'],
            scope=cls.DATA['scope'],
            prompt=cls.DATA['prompt']

        )

    @classmethod
    def g_signup(cls, request):
        try:
            code = request.args.get('code')

            # Generate URL to generate token
            token_url, headers, body = cls.CLIENT.prepare_token_request(
                cls.URL_DICT['token_gen'],
                authorisation_response=request.url,
                # request.base_url is same as DATA['redirect_uri']
                redirect_url=request.base_url,
                code=code)

            # Generate token to access Google API
            token_response = requests.post(
                token_url,
                headers=headers,
                data=body,
                auth=(cls.CLIENT_ID, cls.CLIENT_SECRET))

            # Parse the token response
            cls.CLIENT.parse_request_body_response(json.dumps(token_response.json()))

            # Add token to the  Google endpoint to get the user info
            # oauthlib uses the token parsed in the previous step
            uri, headers, body = cls.CLIENT.add_token(cls.URL_DICT['get_user_info'])

            # Get the user info
            response_user_info = requests.get(uri, headers=headers, data=body)
            info = response_user_info.json()

            return info
        except Exception as e:
            raise e
