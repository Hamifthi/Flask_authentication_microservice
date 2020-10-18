from datetime import datetime, timedelta
import jwt

from main_app import app, db, bcrypt
from config import Config


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=True)
    password = db.Column(db.String(255), nullable=False)
    registration_date = db.Column(db.DateTime, nullable=False, default=datetime.now())
    admin = db.Column(db.Boolean, nullable=False, default=False)

    def __int__(self, email, password, admin=False):
        self.email = email
        self.password = bcrypt.generate_password_hash(password, app.config["BCRYPT_ROUND"]).decode()
        self.admin = admin


    @staticmethod
    def encode_auth_token(user_id):
        try:
            payload = {
                'exp': datetime.now() + timedelta(days=1),
                'iat': datetime.now(),
                'sub': user_id
            }
            return jwt.encode(
                payload=payload,
                key=Config.SECRET_KEY,
                algorithm='HS256'
            )
        except Exception as error:
            return error

    @staticmethod
    def decode_auth_token(auth_token):
        try:
            payload = jwt.decode(auth_token, Config.SECRET_KEY)
            is_deprecated = DeprecatedToken.check_deprecated(auth_token)
            if is_deprecated:
                return 'Token deprecated. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please login again'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'


class DeprecatedToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'deprecated_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    deprecated_on = db.Column(db.DateTime, nullable=False, default=datetime.now())

    def __init__(self, token):
        self.token = token

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_deprecated(token):
        is_deprecated = DeprecatedToken.query.filter(token=token).first()
        if is_deprecated:
            return True
        else:
            return False
