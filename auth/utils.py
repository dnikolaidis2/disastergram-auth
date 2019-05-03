from functools import wraps
from flask import abort, request, current_app
from datetime import timedelta
from auth.models import Token, TokenEnum, hash_token_to_uuid, update_token_table
import jwt


def enforce_json():
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # GET requests do not have json
            if (not request.is_json) and (request.method != 'GET'):
                abort(400, 'REST API call is not json')

            return f(*args, **kwargs)

        return wrapped
    return decorator


def check_token(pub_key, token=None, check_with_db=True):
    if pub_key is None:
        abort(500, "Server error occurred while processing request")

    actual_token = None
    if token is None:
        if request.method == 'GET':
            # check if token was sent with request
            actual_token = request.args.get('token')
            if actual_token is None:
                abort(400, 'Token is not part of request')

            # check if token is not empty
            if actual_token == '':
                abort(400, 'Field token cannot be empty')

        else:
            # check json data
            actual_token = request.json.get('token')
            if actual_token is None:
                abort(400, 'Token is not part of request json')

            if actual_token == '':
                abort(400, 'Field token cannot be empty')
    else:
        if token == '':
            abort(400, 'Field token cannot be empty')

        actual_token = token

    token_payload = None
    # verify token
    try:
        token_payload = jwt.decode(actual_token,
                                   pub_key,
                                   leeway=current_app.config.get('AUTH_LEEWAY', timedelta(seconds=30)), # give 30 second leeway on time checks
                                   issuer='auth',
                                   algorithms='RS256')
    except jwt.InvalidSignatureError:
        # signature of token does not match
        abort(403, 'Invalid token signature')
    except jwt.ExpiredSignatureError:
        # token has expired
        abort(403, 'Token has expired')
    except jwt.InvalidIssuerError:
        # token issuer is invalid
        abort(403, 'Invalid token issuer')
    except jwt.ImmatureSignatureError:
        # token has been used too fast
        abort(403, 'Immature token try again')
    except jwt.exceptions.DecodeError:
        # something went wrong here
        abort(403, 'Invalid token')

    if check_with_db:
        update_token_table()

        token_db = Token.query.get(hash_token_to_uuid(actual_token))
        if token_db is None:
            # If this is reached it means that either the user was deleted while having valid tokens
            # or that there was a major screw up somewhere
            abort(500, 'Invalid token. Token subject probably does not exist')

        if token_db.status == TokenEnum.INACTIVE:
            abort(400, 'User has logged out. Please log back in again.')

    return token_payload


def check_token_sub(token_payload, user):
    if token_payload.get('sub', '') == str(user.id.int): return True
    else: return False


def require_auth(pub_key="PUBLIC_KEY", check_with_db=True):
    if not callable(pub_key):
        pub_key = lambda: current_app.config.get('PUBLIC_KEY')

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            payload = check_token(pub_key(), check_with_db=check_with_db)
            kwargs['token_payload'] = payload
            return f(*args, **kwargs)

        return wrapped
    return decorator
