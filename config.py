import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SQLALCHEMY_DATABASE_URI = F"mysql+pymysql://{os.environ['DB_USERNAME']}:{os.environ['DB_PASSWORD']}@{os.environ['DB_HOST']}/{os.environ['DB_NAME']}"
    SECRET_ACCESS_KEY = os.environ['SECRET_ACCESS_KEY']
    SECRET_REFRESH_KEY = os.environ['SECRET_REFRESH_KEY']

    GOOGLE_CLIENT_ID = os.environ['GOOGLE_CLIENT_ID']
    GOOGLE_CLIENT_SECRET = os.environ['GOOGLE_CLIENT_SECRET']
    GOOGLE_REDIRECT_URI = os.environ['GOOGLE_REDIRECT_URI']


"our own config to load env"
config = Config()
