from flask import Flask
from flask_bcrypt import Bcrypt
from flask_oauthlib.client import OAuth
from app.models import SQLConfig
# from app.utils.linkedin_oauth_base import LinkedinSvc
from config import config


class AppFactory:
    """
    AppFactory for Flask
    """
    bcrypt = None
    oauth = None

    @classmethod
    def create_app(cls):
        try:
            app = Flask(__name__)
            app.secret_key = config.SECRET_ACCESS_KEY

            # OAUTHLIB_INSECURE_TRANSPORT
            # this is to avoid issue OAuth 2.0 only supports https
            # environments
            app.config.update({
                'OAUTHLIB_INSECURE_TRANSPORT': '1'})

            cls.bcrypt = Bcrypt(app)
            cls.oauth = OAuth(app)

            # blueprint registration

            from app.api.user_api import api_pb
            app.register_blueprint(api_pb)

            # Initialize SQlAlchemy
            SQLConfig.initialize()

            # LinkedinSvc(cls.oauth)

            with app.app_context():
                pass
            return app

        except Exception as e:
            raise e


"""Using a static method or __init__ for creating the app instance wouldn't offer the same flexibility and control. A 
static method wouldn't have access to class-specific attributes and wouldn't be aware of changes to the class or its 
inheritance hierarchy. Using __init__ to create the app instance might couple the creation of the instance too 
tightly with the class itself, which can make it harder to adjust configurations and settings dynamically.

To sum up, while it's not strictly required to use a class method for the app factory, it's a convention that 
provides the necessary flexibility for creating a Flask app in different contexts, configurations, and environments. 
It allows you to cleanly separate the app setup logic from the rest of your code and provides a standardized way to 
configure your application."""
