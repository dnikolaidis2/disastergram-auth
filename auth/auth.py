from flask import Blueprint, request, abort, Response

from auth.models import UserSchema, User

from auth import db


bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/user', methods=['POST', 'GET'])
def user():
    if request.method == 'POST':
        # TODO: could you use marshal.dump to do some input testing?
        # Abort if false format
        if not request.is_json:
            abort(400)

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

    if request.method == 'GET':

        user_schema = UserSchema(exclude=['id'])
        # getuser = User.query.get(1)

        # return user_schema.jsonify(getuser)
        # Find if user exists

        reqd_user = request.args.get('username')
        if reqd_user is None:
            # Returns all usernames in a single string
            # ...for debugging reasons
            str = ''
            user_list = User.query.all()
            for user in user_list:
                str = str + user.username + '  '
            return str
        else:
            get_user = User.query.filter(User.username == reqd_user).one()
            return user_schema.jsonify(get_user)

        # Maybe check if they have the required perms?
        # User
        # Return user. Redirecting to its profile page
        # return


@bp.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':

        if not request.is_json:
            abort(400)

        if User.query.filter(User.username == request.json['username']).count() != 0:
            abort(400)
