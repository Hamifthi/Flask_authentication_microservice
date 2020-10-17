import os
from environs import Env


BASE_PATH = os.path.dirname(os.path.abspath(__file__))
env = Env()
env.read_env(recurse=False, path=os.path.join(BASE_PATH, '.env'), override=True)


class Config(object):
    SQLALCHEMY_DATABASE_URI = env('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = True
    TESTING = False
    CSRF_ENABLED = True
    SECRET_KEY = env('SECRET_KEY')
    BCRYPT_ROUND = env('BCRYPT_ROUND')
