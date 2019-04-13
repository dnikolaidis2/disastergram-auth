from flask import Blueprint, request, Response, current_app, jsonify
from auth.models import UserSchema, User
from auth import db
from datetime import datetime, timedelta
from auth.utils import enforce_json, require_auth, check_token
import jwt


bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.errorhandler(400)
def bad_request_handler(error):
    return jsonify(error=error.description), 400


@bp.errorhandler(403)
def bad_request_handler(error):
    return jsonify(error=error.description), 403


@bp.route('/register', methods=['POST'])
@bp.route('/user', methods=['POST'])
@enforce_json()
def user_register():
    # Validate incoming json
    data = UserSchema(exclude=['id']).loads(request.data)
    if data.errors != {}:
        return jsonify(errors=data.errors), 400

    if len(request.json) != 2:         # only one username and password pair expected
        return jsonify(error='Invalid number of arguments'), 400

    # Abort if user already exists
    if User.query.filter(User.username == request.json['username']).count() != 0:
        return jsonify(error='Username ' + request.json['username'] + ' has already been taken'), 400

    # 1. Creates new user according to request params
    # 2. Add to db
    # 3. Commit changes
    new_user = User(username=request.json['username'], password=request.json['password'])
    db.session.add(new_user)
    db.session.commit()

    # Return code 201: 'Created'
    return Response(status=201)


@bp.route('/user/<username>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
@enforce_json()
@require_auth()
def user(username, token):
    if request.method == 'GET':
        user_schema = UserSchema(exclude=['id', 'password'])

        req_user = User.query.filter(User.username == username).one()
        if req_user in None:
            return jsonify(error= 'User ' + request.json['username'] + ' does not exist'), 400

        return user_schema.jsonify(req_user)
    elif request.method == 'PUT':
        # Validate incoming json
        data = UserSchema(exclude=['id']).loads(request.data)
        if data.errors != {}:
            return jsonify(errors=data.errors), 400

        if len(request.json) != 3:  # only one username and password pair expected
            return jsonify(error='Invalid number of arguments'), 400

        # Abort if user already exists
        req_user = User.query.filter(User.username == username)
        if req_user is None:
            return jsonify(error= 'User ' + username + ' does not exist'), 400

        if User.query.filter(User.username == request.json['username']).one() is not None:
            return jsonify(error='Username ' + request.json['username'] + ' has already been taken'), 400

        req_user.username = request.json['username']
        req_user.set_password(request.json['password'])

        db.commit()

    elif request.method == 'PATCH':
        pass
    elif request.method == 'DELETE':
        pass


@bp.route('/logout', methods=['DELETE'])
@bp.route('/refresh', methods=['PUT'])
@bp.route('/login', methods=['POST'])
@bp.route('/token', methods=['POST', 'PUT', 'DELETE'])
@enforce_json()
def login():
    if request.method == 'POST':
        # Validate incoming json
        data = UserSchema(exclude=['id']).loads(request.data)
        if data.errors != {}:
            return jsonify(errors=data.errors), 400

        if len(request.json) != 2:  # only one username and password pair expected
            return jsonify(error='Invalid number of arguments'), 400

        user = User.query.filter(User.username == request.json['username']).one()

        if user is None:
            return jsonify(error='Incorrect username or password'), 400

        if not user.check_password(request.json['password']):
            return jsonify(error='Incorrect username or password'), 400

        payload = {
            'iss': 'auth_server',                               # TODO: WHO ARE WE?
            'sub': request.json['username'],                    # TODO: Should we hash username or just plain text?
            'exp': datetime.utcnow() + timedelta(minutes=10),   # 10 minute token
            'nbf': datetime.utcnow()
        }

        token = jwt.encode(payload, current_app.config['SECRET_KEY'])

        # TODO do some database storage thingies?

        return jsonify(token=token.decode('utf-8'))
    elif request.method == 'PUT':
        # TODO check if login has been invalidated

        if len(request.json) != 1:
            return jsonify(error='Invalid number of arguments'), 400

        token = check_token(current_app.config['SECRET_KEY'])

        payload = {
            'iss': 'auth_server',                               # TODO: WHO ARE WE?
            'sub': token['sub'],                                # TODO: Should we hash username or just plain text?
            'exp': datetime.utcnow() + timedelta(minutes=10),   # 10 minute token
            'nbf': datetime.utcnow()
        }

        token = jwt.encode(payload, current_app.config['SECRET_KEY'])

        return jsonify(token=token.decode('utf-8'))
    elif request.method == 'DELETE':
        pass
