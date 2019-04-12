from flask import Blueprint, request, abort, Response, current_app, jsonify

from auth.models import UserSchema, User

from auth import db

from functools import wraps

import jwt, time


bp = Blueprint('auth', __name__, url_prefix='/auth')


def enforce_json():
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not request.is_json:
                abort(400)

            return f(*args, **kwargs)

        return wrapped
    return decorator


def require_auth():
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            return f(*args, **kwargs)

        return wrapped
    return decorator


@bp.route('/user', methods=['POST'])
@enforce_json()
def user_register():
    # TODO: could you use marshal.dump to do some input testing?

    # Abort if user already exists
    if User.query.filter(User.username == request.json['username']).count() != 0:
        abort(400)

    # 1. Creates new user according to request params
    # 2. Add to db
    # 3. Commit changes
    new_user = User(username=request.json['username'], password=request.json['password'])
    db.session.add(new_user)
    db.session.commit()

    # Return code 201: 'Created'
    return Response(status=201)


@bp.route('/user/<username>')
def user_get(username):
    # TODO authenticate user
    user_schema = UserSchema(exclude=['id', 'password'])

    if username == 'all':
        # Returns all usernames in a single string
        # ...for debugging reasons
        str = ''
        user_list = User.query.all()
        for user in user_list:
            str = str + user.username + '  '
        return str
    else:

        get_user = User.query.filter(User.username == username).one()
        return user_schema.jsonify(get_user)

    # Maybe check if they have the required perms?
    # User
    # Return user. Redirecting to its profile page
    # return


@bp.route('/login', methods=['POST'])
@enforce_json()
def login():
    # TODO: could you use marshal.dump to do some input testing?

    user = User.query.filter(User.username == request.json['username']).one()

    if user is None:
        abort(400)

    if not user.check_password(request.json['password']):
        abort(400)

    payload = {
        'iss': 'auth_server',                               # TODO: WHO ARE WE
        'sub': request.json['username'],
        'exp': int(time.mktime(time.gmtime())) + 60*10,     # 10 minute token
        'nbf': int(time.mktime(time.gmtime()))
    }

    token = jwt.encode(payload, current_app.config['SECRET_KEY'])

    return jsonify(token=token)


# refresh
# logout
