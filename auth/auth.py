from flask import Blueprint, Response, current_app, jsonify, abort
from auth.models import UserSchema, User
from auth import db
from datetime import datetime, timedelta
from auth.utils import enforce_json, require_auth
from flask_apispec import use_kwargs, doc
from marshmallow import fields
import jwt


bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.errorhandler(400)
def bad_request_handler(error):
    return jsonify(error=error.description), 400


@bp.errorhandler(403)
def bad_request_handler(error):
    return jsonify(error=error.description), 403


@bp.errorhandler(500)
def server_error_handler(error):
    return jsonify(error=error.description), 500


@doc(description="Simple root endpoint for clients to check connection with auth server")
@bp.route('/')
def root():
    return jsonify(status='OK')


register_dict = {'username': fields.Str(required=True),
                 'password': fields.Str(required=True)}


@doc(tags=['user'],
     description='User registration endpoint',
     params={
        'username': {
            'description': 'Desired username',
            'in': 'body',
            'type': 'string',
            'required': True
        },
        'password': {
            'description': 'Users password',
            'in': 'body',
            'type': 'string',
            'required': True
        }
     },
     responses={
         '400: BadRequest': {
             "description": "Given input could not be validated",
             "example": {
                 "error": "Username flamboozle has already been taken"
             }
         },
         '201: Created': {
             "description": "Successfully registered user"
         }
     })
@bp.route('/register', methods=['POST'])
@bp.route('/user', methods=['POST'])
@enforce_json()
@use_kwargs(register_dict, apply=True)
def user_register(**kwargs):
    # Validate incoming json
    if kwargs.keys() != register_dict.keys():
        abort(400, 'Invalid arguments')

    username = kwargs.get('username')
    password = kwargs.get('password')

    # Abort if user already exists
    if User.query.filter(User.username == username).count() != 0:
        abort(400, 'Username {} has already been taken'.format(repr(username)))

    # 1. Creates new user according to request params
    # 2. Add to db
    # 3. Commit changes
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    # Return code 201: 'Created'
    return Response(status=201)


@doc(tags=['user'],
     description='Get user info based on username',
     params={
        'username': {
            'description': 'Users username',
            'in': 'path',
            'type': 'string',
            'required': True
        },
        'token': {
            'description': 'Authentication token signed by auth server',
            'in': 'query',
            'type': 'string',
            'required': True
        }
     },
     responses={
         '400: BadRequest': {
             "description": "Given input could not be validated",
             "example": {
                 "error": "Username flamboozle does not exist"
             }
         },
         '403: Forbidden': {
             "description": "Authentication off token has failed",
             "example": {
                 "error": "Invalid token signature"
             }
         },
         '200: OK': {
             "description": "Query successful",
             "example": {
                 "username": "flamboozle"
             }
         }
     })
@bp.route('/user/<username>')
@enforce_json()
@require_auth()
def user_read(username, token_payload):
    user_schema = UserSchema(exclude=['password'])

    # validate that user exists
    req_user = User.query.filter(User.username == username).one_or_none()
    if req_user is None:
        abort(400, 'User {} does not exist'.format(repr(username)))

    # validate that the token came form the correct user
    if token_payload['sub'] != req_user.id:
        abort(403, 'Token subject and username could not be matched')

    return user_schema.jsonify(req_user)


user_replace_dict = {'token': fields.Str(required=True),
                     'new_username': fields.Str(required=True),
                     'new_password': fields.Str(required=True)}


@doc(tags=['user'],
     description='Completely replace users info with new info',
     params={
        'username': {
            'description': 'Users username',
            'in': 'path',
            'type': 'string',
            'required': True
        },
        'token': {
            'description': 'Authentication token signed by auth server',
            'in': 'body',
            'type': 'string',
            'required': True
        },
        'new_username': {
            'description': 'New user username',
            'in': 'body',
            'type': 'string',
            'required': True
        },
        'new_password': {
            'description': 'New user password',
            'in': 'body',
            'type': 'string',
            'required': True
        }
     },
     responses={
         '400: BadRequest': {
             "description": "Given input could not be validated",
             "example": {
                 "error": "Username flamboozle does not exist"
             }
         },
         '403: Forbidden': {
             "description": "Authentication off token has failed",
             "example": {
                 "error": "Invalid token signature"
             }
         },
         '200: OK': {
             "description": "Query successful",
             "example": {
                 "status": "OK"
             }
         }
     })
@bp.route('/user/<username>', methods=['PUT'])
@enforce_json()
@use_kwargs(user_replace_dict, apply=True)
@require_auth()
def user_replace(username, token_payload, **kwargs):
    # TODO Accept only User object
    # Validate incoming json
    if kwargs.keys() != user_replace_dict.keys():
        abort(400, 'Invalid arguments')

    new_username = kwargs.get('new_username')
    new_password = kwargs.get('new_password')

    # Could not find user
    req_user = User.query.filter(User.username == username).one_or_none()
    if req_user is None:
        abort(400, 'User {} does not exist'.format(repr(username)))

    # validate that the token came form the correct user
    if token_payload['sub'] != req_user.id:
        abort(403, 'Token subject and username could not be matched')

    # Username has not changed
    if req_user.username == new_username:
        abort(400, "Users username has not changed please user this endpoint "
                   "for replacing resource not updating it")

    req_user.username = new_username
    req_user.set_password(new_password)

    db.session.commit()

    return jsonify(status='OK')


user_update_dict = {'token': fields.Str(required=True),
                    'new_username': fields.Str(required=False),
                    'new_password': fields.Str(required=False)}


@doc(tags=['user'],
     description='Update parts of the users info',
     params={
        'username': {
            'description': 'Users username',
            'in': 'path',
            'type': 'string',
            'required': True
        },
        'token': {
            'description': 'Authentication token signed by auth server',
            'in': 'body',
            'type': 'string',
            'required': True
        },
        'new_username': {
            'description': 'New user username',
            'in': 'body',
            'type': 'string',
            'required': False
        },
        'new_password': {
            'description': 'New user password',
            'in': 'body',
            'type': 'string',
            'required': False
        }
     },
     responses={
         '400: BadRequest': {
             "description": "Given input could not be validated",
             "example": {
                 "error": "Username flamboozle does not exist"
             }
         },
         '403: Forbidden': {
             "description": "Authentication off token has failed",
             "example": {
                 "error": "Invalid token signature"
             }
         },
         '200: OK': {
             "description": "Query successful",
             "example": {
                 "status": "OK"
             }
         }
     })
@bp.route('/user/<username>', methods=['PATCH'])
@enforce_json()
@use_kwargs(user_update_dict, apply=True)
@require_auth()
def user_update(username, token_payload, **kwargs):
    # TODO Accept only User object
    # Validate incoming json
    if not (2 <= len(kwargs.keys()) <= len(user_replace_dict.keys())):
        abort(400, 'Invalid arguments')

    # Could not find user
    req_user = User.query.filter(User.username == username).one_or_none()
    if req_user is None:
        abort(400, 'User {} does not exist'.format(repr(username)))

    # validate that the token came form the correct user
    if token_payload['sub'] != req_user.id:
        abort(403, 'Token subject and username could not be matched')

    new_username = kwargs.get('new_username')
    if new_username is not None:
        req_user.username = new_username

    new_password = kwargs.get('new_password')
    if new_password is not None:
        req_user.set_password(new_password)

    db.session.commit()

    return jsonify(status='OK')


user_delete_dict = {'token': fields.Str(required=True)}


@doc(tags=['user'],
     description='Deletes user',
     params={
        'token': {
            'description': 'Authentication token signed by auth server',
            'in': 'body',
            'type': 'string',
            'required': True
        }
     },
     responses={
         '400: BadRequest': {
             "description": "Given input could not be validated",
             "example": {
                 "error": "Token is not part of request form"
             }
         },
         '403: Forbidden': {
             "description": "Authentication off token has failed",
             "example": {
                 "error": "Invalid token signature"
             }
         },
         '200: OK': {
             "description": "Query successful",
             "example": {
                 "status": "OK"
             }
         }
     })
@bp.route('/user/<username>', methods=['DELETE'])
@enforce_json()
@use_kwargs(user_delete_dict)
@require_auth()
def user_del(username, token_payload,  **kwargs):
    # Validate incoming json
    if kwargs.keys() != user_delete_dict.keys():
        abort(400, 'Invalid arguments')

    # Could not find user
    req_user = User.query.filter(User.username == username).one_or_none()
    if req_user is None:
        abort(400, 'User {} does not exist'.format(repr(username)))

    # validate that the token came form the correct user
    if token_payload['sub'] != req_user.id:
        abort(403, 'Token subject and username could not be matched')

    db.session.delete(req_user)
    db.session.commit()

    return jsonify(status='OK')


login_dict = {'username': fields.String(required=True),
              'password': fields.String(required=True)}


@doc(tags=['token'],
     description='Login as user username with password',
     params={
         'username': {
             'description': 'Users username',
             'in': 'body',
             'type': 'string',
             'required': True
         },
         'password': {
            'description': 'Users password',
            'in': 'body',
            'type': 'string',
            'required': True
         }
     },
     responses={
         '400: BadRequest': {
             "description": "Given input could not be validated",
             "example": {
                 "error": "Incorrect username or password"
             }
         },
         '200: OK': {
             "description": "Query successful",
             "example": {
                 "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE1NTU4ODQ"
                          "1NTksImV4cCI6MTU4NzQyMDU1OSwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmN"
                          "vbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5"
                          "jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.McHhw5XmHOPHhI9BrXEVD5ueWYo"
                          "LLwsu_1XSxbN_3sc"
             }
         }
     })
@bp.route('/login', methods=['POST'])
@bp.route('/token', methods=['POST'])
@enforce_json()
@use_kwargs(login_dict, apply=True)
def login(**kwargs):
    # Validate incoming json
    if kwargs.keys() != login_dict.keys():
        abort(400, 'Invalid arguments')

    username = kwargs.get('username')
    password = kwargs.get('password')

    req_user = User.query.filter(User.username == username).one_or_none()
    if req_user is None:
        abort(400, 'Incorrect username or password')

    if not req_user.check_password(password):
        abort(400, 'Incorrect username or password')

    payload = {
        'iss': 'auth_server',                               # TODO: WHO ARE WE?
        'sub': req_user.id,
        'exp': datetime.utcnow() + timedelta(minutes=10),   # 10 minute token
        'nbf': datetime.utcnow()
    }

    private_key = current_app.config.get('PRIVATE_KEY')
    if private_key is None:
        abort(500, "Server error occurred while processing request")

    token = jwt.encode(payload, private_key, algorithm='RS256')

    return jsonify(token=token.decode('utf-8'))


refresh_dict = {'token': fields.String(required=True)}


@doc(tags=['token'],
     description='Login as user username with password',
     params={
         'token': {
            'description': 'Authentication token signed by auth server',
            'in': 'body',
            'type': 'string',
            'required': True
        }
     },
     responses={
         '400: BadRequest': {
             "description": "Given input could not be validated",
             "example": {
                 "error": "Invalid arguments"
             }
         },
         '403: Forbidden': {
             "description": "Authentication off token has failed",
             "example": {
                 "error": "Invalid token signature"
             }
         },
         '200: OK': {
             "description": "Query successful",
             "example": {
                 "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE1NTU4ODQ"
                          "1NTksImV4cCI6MTU4NzQyMDU1OSwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmN"
                          "vbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5"
                          "jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.McHhw5XmHOPHhI9BrXEVD5ueWYo"
                          "LLwsu_1XSxbN_3sc"
             }
         }
     })
@bp.route('/refresh', methods=['PUT'])
@bp.route('/token', methods=['PUT'])
@enforce_json()
@use_kwargs(refresh_dict, apply=True)
@require_auth()
def refresh_token(token_payload, **kwargs):
    # TODO Check if the token is in the blacklist
    # TODO add previous token to blacklist???

    # Validate incoming json
    if kwargs.keys() != refresh_dict.keys():
        abort(400, 'Invalid arguments')

    payload = {
        'iss': 'auth_server',                               # TODO: WHO ARE WE?
        'sub': token_payload['sub'],
        'exp': datetime.utcnow() + timedelta(minutes=10),   # 10 minute token
        'nbf': datetime.utcnow()
    }

    private_key = current_app.config.get('PRIVATE_KEY')
    if private_key is None:
        abort(500, "Server error occurred while processing request")

    token = jwt.encode(payload, private_key, algorithm='RS256')

    return jsonify(token=token.decode('utf-8'))


logout_dict = {'token': fields.String(required=True)}


@doc(tags=['token'],
     description='Login as user username with password',
     params={
         'token': {
            'description': 'Authentication token signed by auth server',
            'in': 'body',
            'type': 'string',
            'required': True
        }
     },
     responses={
         '400: BadRequest': {
             "description": "Given input could not be validated",
             "example": {
                 "error": "Invalid arguments"
             }
         },
         '403: Forbidden': {
             "description": "Authentication off token has failed",
             "example": {
                 "error": "Invalid token signature"
             }
         },
         '200: OK': {
             "description": "Query successful",
             "example": {
                 "status": "OK"
             }
         }
     })
@bp.route('/logout', methods=['DELETE'])
@bp.route('/token', methods=['DELETE'])
@enforce_json()
@use_kwargs(logout_dict, apply=True)
@require_auth()
def logout(**kwargs):
    # Validate incoming json
    if kwargs.keys() != refresh_dict.keys():
        abort(400, 'Invalid arguments')

    # TODO do stuff to handle things

    return jsonify(status='OK')


@doc(tags=['public_key'],
     description='Authentication servers public key',
     responses={
         '200': {
             "description": "The servers public key is returned as a json object",
             "example": {
                 "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDNE1RK4tX2bGmA5ZWco+bPy/HS6v9yTg91ut9W6AtC4d+"
                               "Ie2o6IzPxVvJENYziIzteTGyEdQiW3NJP0lx1f6Zgjd9u2/h1PJl9MHYwZFJ2IpzimhDaASxv9CmDL7rzrZ"
                               "jupWCy1gwOjWQy8TQ1+Ema1w5dSXMA7GdU7JR745+CrXhTJrE9rQdIFuZeRQP5Q6zooAWMoCHax2xuv8v6r"
                               "9tP3J7HLSTSoi4I+/9M5ztLHh1CjPyg/btR118Z/BRRZvaPrXy0U+GdoEfQSAjLC0AEgaa1Z0Z0bk2NLc4/"
                               "kDIEW7w67rc5v53ewXO/I+pzUOxrAIO6PKu149JAdd/AibdXComjNG31KB6CQcGyG/PQU0hEBk96p2BGFyy"
                               "gtOJFr4hNP9usYHt2xFf+kEBkXuTMpKd8rwhIHK/SB+KkV0eHFP7lK9SFZvcQ+oSaJawJE1BBEm8ytvAtfP"
                               "NAchl6YJPLxfodXjDZ7QmtmnNODxCOhc+7EgH0VHZrLRQVQFSzw8bM9xQ7DCI7fglOSuHKwkN2E/HsKuD19"
                               "i5UEpp+9wq+WMD719ZVwXkjbxKWq8MLDdIZNlYqNn9l8/NMdVzI6TdeeAPZESdNjXhlgrxlw0LpEuWBNmFe"
                               "iTXsZstCmDCC6OOZDJApDIS8EIQh6TiTuA7v1FT1tCfNCG29JmI+iDBCeQ== dimitris@Gideon"
             }
         }
     })
@bp.route('/pubkey')
def pub_key():
    public_key = current_app.config.get('PUBLIC_KEY')
    if public_key is None:
        abort(500, "Server error occurred while processing request")

    return jsonify(public_key=public_key.decode('utf-8'))
