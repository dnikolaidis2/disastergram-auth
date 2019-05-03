from flask import Blueprint, current_app, jsonify, abort, request
from auth.models import UserSchema, User, Token, update_token_table, hash_token_to_uuid
from auth import db
from datetime import datetime, timedelta
from auth.utils import enforce_json, require_auth, check_token, check_token_sub
from flask_apispec import use_kwargs, doc
from marshmallow import fields
from uuid import UUID
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


@doc(description="Simple health check endpoint")
@bp.route('/')
def root():
    return jsonify(status='OK')

# --------------------------------      user        -------------------------------------------------


register_dict = {'username': fields.Str(required=True),
                 'password': fields.Str(required=True)}


@doc(tags=['user'],
     description='User registration endpoint',
     params={
        'username': {
            'description': 'New users username',
            'in': 'body',
            'type': 'string',
            'required': True
        },
        'password': {
            'description': 'New users password',
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
             "description": "Successfully registered user",
             "example": {
                 "id":          "183439473529470444081084392815720982525",
                 "username":    "doodle"
             }

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

    # check if arguments are not empty
    if username == '':
        abort(400, 'field username cannot be empty')

    if password == '':
        abort(400, 'field password cannot be empty')

    # Abort if user already exists
    if User.query.filter(User.username == username).count() != 0:
        abort(400, 'Username {} has already been taken'.format(repr(username)))

    # 1. Creates new user according to request params
    # 2. Add to db
    # 3. Commit changes
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    # return new_user
    resp = UserSchema().jsonify(new_user)
    resp.status_code = 201

    # Return code 201: 'Created'
    return resp


# TODO remove dis!!!
@bp.route('/users/all', methods=['GET'])
def get_everyone():
    users = User.query.all()

    user_schema = UserSchema()
    return user_schema.jsonify(users, many=True)


# --------------------------------      user/username   -------------------------------------------------


@doc(tags=['user'],
     description='Get user info based on username. '
                 'If token is present get all user data else get only public facing info',
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
                 "id":       "183439473529470444081084392815720982525",
                 "username": "doodle"
             }
         }
     })
@bp.route('/user/<username>')
def user_read(username):
    token = request.args.get('token')
    if token is None:
        # validate that user exists
        req_user = User.query.filter(User.username == username).one_or_none()
        if req_user is None:
            abort(400, 'User {} does not exist'.format(repr(username)))

        # Unvalidated GET method. Exclude any sensitive data (if any)
        return UserSchema().jsonify(req_user)
    else:
        token_payload = check_token(current_app.config.get('PUBLIC_KEY'), token)

        # validate that user exists
        req_user = User.query.filter(User.username == username).one_or_none()
        if req_user is None:
            abort(400, 'User {} does not exist'.format(repr(username)))

        # validate that the token came form the correct user
        if not check_token_sub(token_payload, req_user):
            abort(403, 'Token subject could not be verified')

        # Validated GET method should return both public and sensitive data
        return UserSchema().jsonify(req_user)


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
    # Validate incoming json
    if kwargs.keys() != user_replace_dict.keys():
        abort(400, 'Invalid arguments')

    new_username = kwargs.get('new_username')
    new_password = kwargs.get('new_password')

    # Check if json objects are not empty
    if new_username == '':
        abort(400, 'Field new_username cannot be empty')

    if new_password == '':
        abort(400, 'Field new_password cannot be empty')

    # Could not find user
    req_user = User.query.filter(User.username == username).one_or_none()
    if req_user is None:
        abort(400, 'User {} does not exist'.format(repr(username)))

    # validate that the token came form the correct user
    if not check_token_sub(token_payload, req_user):
        abort(403, 'Token subject could not be verified')

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
    # Validate incoming json
    if not (2 <= len(kwargs.keys()) <= len(user_replace_dict.keys())):
        abort(400, 'Invalid arguments')

    # Could not find user
    req_user = User.query.filter(User.username == username).one_or_none()
    if req_user is None:
        abort(400, 'User {} does not exist'.format(repr(username)))

    # validate that the token came form the correct user
    if not check_token_sub(token_payload, req_user):
        abort(403, 'Token subject could not be verified')

    new_username = kwargs.get('new_username')
    if new_username is not None:
        if new_username == '':
            abort(400, 'Field new_username cannot be empty.')
        req_user.username = new_username

    new_password = kwargs.get('new_password')
    if new_password is not None:
        if new_password == '':
            abort(400, 'Field new_password cannot be empty.')
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
    if not check_token_sub(token_payload, req_user):
        abort(403, 'Token subject could not be verified')

    db.session.delete(req_user)
    db.session.commit()

    return jsonify(status='OK')


# --------------------------------      user/user_id   -------------------------------------------------


@doc(tags=['user'],
     description='Get user info by user id. If token is present get all user data else only public facing data',
     params={
        'user_id': {
            'description': 'Users id',
            'in': 'path',
            'type': 'int',
            'required': True
        },
        'token': {
            'description': 'Authentication token signed by auth server',
            'in': 'query',
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
                 "id":       1,
                 "username": "flamboozle"
             }
         }
     })
@bp.route('/user/<int:user_id>')
def user_read_id(user_id):
    token = request.args.get('token')
    if token is None:
        # validate that user exists
        req_user = User.query.get(UUID(int=user_id))
        if req_user is None:
            abort(400, 'User {} does not exist'.format(repr(user_id)))

        # Unvalidated GET method. Exclude any sensitive data(if any)
        return UserSchema().jsonify(req_user)
    else:
        token_payload = check_token(current_app.config.get('PUBLIC_KEY'), token)

        # validate that user exists
        req_user = User.query.get(UUID(int=user_id))
        if req_user is None:
            abort(400, 'User {} does not exist'.format(repr(user_id)))

        # validate that the token came form the correct user
        if not check_token_sub(token_payload, req_user):
            abort(403, 'Token subject could not be verified')

        # Validated GET method should return both public and sensitive data
        return UserSchema().jsonify(req_user)


@doc(tags=['user'],
     description='Completely replace users info with new info by user id',
     params={
        'user_id': {
            'description': 'Users id',
            'in': 'path',
            'type': 'int',
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
@bp.route('/user/<int:user_id>', methods=['PUT'])
@enforce_json()
@use_kwargs(user_replace_dict, apply=True)
@require_auth()
def user_replace_id(user_id, token_payload, **kwargs):
    # Validate incoming json
    if kwargs.keys() != user_replace_dict.keys():
        abort(400, 'Invalid arguments')

    new_username = kwargs.get('new_username')
    new_password = kwargs.get('new_password')

    # Check if json fields are not empty
    if new_username == '':
        abort(400, 'Field new_username cannot be empty')

    if new_password == '':
        abort(400, 'Field new_password cannot be empty')

    # Could not find user
    req_user = User.query.get(UUID(int=user_id))
    if req_user is None:
        abort(400, 'User {} does not exist'.format(repr(user_id)))

    # validate that the token came form the correct user
    if not check_token_sub(token_payload, req_user):
        abort(403, 'Token subject could not be verified')

    # Username has not changed
    if req_user.username == new_username:
        abort(400, "Users username has not changed please user this endpoint "
                   "for replacing resource not updating it")

    req_user.username = new_username
    req_user.set_password(new_password)

    db.session.commit()

    return jsonify(status='OK')


@doc(tags=['user'],
     description='Update parts of the users info by user id',
     params={
        'user_id': {
            'description': 'Users id',
            'in': 'path',
            'type': 'int',
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
@bp.route('/user/<int:user_id>', methods=['PATCH'])
@enforce_json()
@use_kwargs(user_update_dict, apply=True)
@require_auth()
def user_update_id(user_id, token_payload, **kwargs):
    # Validate incoming json
    if not (2 <= len(kwargs.keys()) <= len(user_replace_dict.keys())):
        abort(400, 'Invalid arguments')

    # Could not find user
    req_user = User.query.get(UUID(int=user_id))
    if req_user is None:
        abort(400, 'User with id {} does not exist'.format(repr(user_id)))

    # validate that the token came form the correct user
    if not check_token_sub(token_payload, req_user):
        abort(403, 'Token subject could not be verified')

    new_username = kwargs.get('new_username')
    if new_username is not None:
        if new_username == '':
            abort(400, 'Field new_username cannot be empty')
        req_user.username = new_username

    new_password = kwargs.get('new_password')
    if new_password is not None:
        if new_password == '':
            abort(400, 'Field new_password cannot be empty')
        req_user.set_password(new_password)

    db.session.commit()

    return jsonify(status='OK')


@doc(tags=['user'],
     description='Deletes user based on user_id',
     params={
        'user_id': {
            'description': 'Users id',
            'in': 'path',
            'type': 'int',
            'required': True
        },
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
@bp.route('/user/<int:user_id>', methods=['DELETE'])
@enforce_json()
@use_kwargs(user_delete_dict)
@require_auth()
def user_del_id(user_id, token_payload,  **kwargs):
    # Validate incoming json
    if kwargs.keys() != user_delete_dict.keys():
        abort(400, 'Invalid arguments')

    # Could not find user
    req_user = User.query.get(UUID(int=user_id))
    if req_user is None:
        abort(400, 'User with id {} does not exist'.format(repr(user_id)))

    # validate that the token came form the correct user
    if not check_token_sub(token_payload, req_user):
        abort(403, 'Token subject could not be verified')

    db.session.delete(req_user)
    db.session.commit()

    return jsonify(status='OK')


# --------------------------------      token     -------------------------------------------------


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
        'iss': 'auth',                                      # TODO: WHO ARE WE?
        'sub': str(req_user.id.int),
        'exp': datetime.utcnow() + timedelta(hours=2),      # 2 hour token
        'nbf': datetime.utcnow()
    }

    private_key = current_app.config.get('PRIVATE_KEY')
    if private_key is None:
        abort(500, "Server error occurred while processing request")

    token = jwt.encode(payload, private_key, algorithm='RS256')

    update_token_table(True)

    new_token = Token(token)
    db.session.add(new_token)
    db.session.commit()

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
    # Validate incoming json
    if kwargs.keys() != refresh_dict.keys():
        abort(400, 'Invalid arguments')

    payload = {
        'iss': 'auth',                                      # TODO: WHO ARE WE?
        'sub': token_payload['sub'],
        'exp': datetime.utcnow() + timedelta(hours=2),      # 2 hour token
        'nbf': datetime.utcnow()
    }

    private_key = current_app.config.get('PRIVATE_KEY')
    if private_key is None:
        abort(500, "Server error occurred while processing request")

    token = jwt.encode(payload, private_key, algorithm='RS256')

    new_token = Token(token)
    db.session.add(new_token)
    db.session.commit()

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
def logout(token_payload, **kwargs):
    # Validate incoming json
    if kwargs.keys() != logout_dict.keys():
        abort(400, 'Invalid arguments')

    token = kwargs.get('token')

    token_db = Token.query.get(hash_token_to_uuid(token))
    if token_db is None:
        # If this is reached it means that either the user was deleted while having valid tokens
        # or that there was a major screw up somewhere
        abort(500, 'Invalid token. Token subject probably does not exist')

    token_db.set_inactive()

    db.session.commit()

    return jsonify(status='OK')


# --------------------------------      public_key     -------------------------------------------------

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
