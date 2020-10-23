from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask import request
from flask import make_response
from flask import jsonify
from flask import redirect
from flask_login import login_user, logout_user, current_user, login_required
# from models import User, DeprecatedToken
from oauth_provider import OAuthSignIn
import config

app = Flask(__name__)
app.config.from_object(config.Config)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)


@app.route('/v1/register', methods=['POST'])
def register():
    posted_data = request.get_json()
    user = User.query.filter_by(email=posted_data.get('name')).first()
    if not user:
        try:
            user = User(
                email=posted_data.get('email'),
                password=posted_data.get('password')
            )
            db.session.add(user)
            db.session.commit()
            auth_token = user.encode_auth_token(user.id)
            response = {
                'status': 'Success',
                'message': 'successfully registered user',
                'auth_token': auth_token
            }
            return make_response(jsonify(response)), 201
        except Exception as error:
            response = {
                'status': 'Failure',
                'error_message': error
            }
            return make_response(jsonify(response)), 401
    else:
        response = {
            'status': 'Failure',
            'message': 'This user already exists.'
        }
        return make_response(jsonify(response)), 400


@app.route('/v1/login', methods=['POST'])
def login():
    posted_data = request.get_json()
    try:
        user = User.query.filter_by(email=posted_data.get('email')).first()
        if user and bcrypt.check_password_hash(user.password, posted_data.get('password')):
            auth_token = user.encode_auth_token(user.id)
            if auth_token:
                response = {
                    'status': 'Success',
                    'message': 'User successfully login',
                    'auth_token': auth_token
                }
                make_response(jsonify(response)), 200
        else:
            response = {
                'status': 'Failure',
                'message': 'User not found',
            }
            make_response(jsonify(response)), 404
    except Exception as error:
        response = {
            'status': 'Failure',
            'message': error
        }
        make_response(jsonify(response)), 500


@app.route('/v1/status', methods=['GET'])
def user_status():
    auth_header = request.headers.get('Authorization')
    if auth_header:
        try:
            auth_token = auth_header.split(" ")[1]
        except IndexError:
            responseObject = {
                'status': 'fail',
                'message': 'Bearer token malformed.'
            }
            return make_response(jsonify(responseObject)), 401
    else:
        auth_token = None
    if auth_token:
        payload_user_part = User.decode_auth_token(auth_token)
        if not isinstance(payload_user_part, str):
            user = User.query.filter(id=payload_user_part).first()
            response = {
                'status': 'Success',
                'data': {
                    'user_id': user.id,
                    'user_email': user.email,
                    'admin': user.admin,
                    'registration_date': user.registration_date
                }
            }
            return make_response(jsonify(response)), 200
        response = {
            'status': 'Failure',
            'message': payload_user_part
        }
        return make_response(jsonify(response)), 401
    else:
        response = {
            'status': 'Failure',
            'message': 'Auth token is invalid'
        }
        return make_response(jsonify(response)), 401


@app.route('/v1/logout')
def logout():
    auth_header = request.headers.get('Authorization')
    if auth_header:
        auth_token = auth_header.split(' ')[1]
    else:
        auth_token = None
    if auth_token:
        payload_user_part = User.decode_auth_token(auth_token)
        if not isinstance(payload_user_part, str):
            deprecated_token = DeprecatedToken(auth_token)
            try:
                db.session.add(deprecated_token)
                db.session.commit()
                response = {
                    'status': 'Success',
                    'message': 'User successfully logged out'
                }
                make_response(jsonify(response)), 200
            except Exception as error:
                response = {
                    'status': 'Failure',
                    'message': error
                }
                make_response(jsonify(response)), 500
        response = {
            'status': 'Failure',
            'message': payload_user_part
        }
        make_response(jsonify(response)), 401
    else:
        response = {
            'status': 'Failure',
            'message': 'Auth token is invalid'
        }
        make_response(jsonify(response)), 403


@app.route('/v1/authorize/<provider>')
def authorize_provider(provider):
    if not current_user.is_anonymous():
        response = {
            'status': 'Failure',
            'message': 'You may log in before please log out first'
        }
        return make_response(jsonify(response)), 403
    oauth = OAuthSignIn.get_provider(provider)
    return oauth.authorize()


@app.route('/v1/callback/<provider>')
def oauth_callback(provider):
    if not current_user.is_anonymous():
        response = {
            'status': 'Failure',
            'message': 'You may log in before please log out first'
        }
        return make_response(jsonify(response)), 403
    oauth = OAuthSignIn.get_provider(provider)
    username, email = oauth.callback()
    if email is None:
        # I need a valid email address for my user identification
        response = {
            'status': 'Failure',
            'message': 'Need A valid email'
        }
        return make_response(jsonify(response)), 400
    # Look if the user already exists
    user = User.query.filter_by(email=email).first()
    if not user:
        # We can do more work here to ensure a unique nickname, if you
        # require that.
        user = User(email=email)
        db.session.add(user)
        db.session.commit()
    # Log in the user, by default remembering them for their next visit
    # unless they log out.
    login_user(user, remember=True)
    response = {
            'status': 'Success',
            'message': 'User logged in successfully'
        }
    return make_response(jsonify(response)), 200


if __name__ == '__main__':
    db.init_app(app)
    migrate.init_app(app, db)
    app.run('localhost', 5000, app.config["DEBUG"])
