from flask import Flask
from flask_bcrypt import Bcrypt

from app.models import SQLConfig


# from config import config


class AppFactory:
    """
    AppFactory for Flask
    Holds the flask app instance
    Holds the sqlalchemy session
    """
    bcrypt = None

    @classmethod
    def create_app(cls):
        try:
            app = Flask(__name__)

            app.config.update({
                                  'OAUTHLIB_INSECURE_TRANSPORT': '1'})  # this is to set our environment to https
            # because OAuth 2.0 only supports https environments

            cls.bcrypt = Bcrypt(app)

            # blueprint registration

            from app.api.user_api import api_pb
            app.register_blueprint(api_pb)

            # Initialize SQlAlchemy
            SQLConfig.initialize()

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
