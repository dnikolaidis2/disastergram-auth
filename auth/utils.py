from functools import wraps
from flask import abort, request, current_app
from datetime import timedelta
import jwt


def enforce_json():
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # GET requests do not have json
            if (not request.is_json) and (request.method != 'GET'):
                abort(400, error='REST API call is not json')

            return f(*args, **kwargs)

        return wrapped
    return decorator


def check_token(secret, username=None):
    token = ''
    if request.method == 'GET':
        # check if token was sent with request
        if request.args == {}:
            abort(400, 'Token is not part of request')

        # check if token is not empty
        token = request.args['token']
        if token == '':
            abort(400, 'Token field is empty')
    else:
        # check json data
        if request.json['token'] == '':
            abort(400, 'Token is not part of request form')

        token = request.json['token']

    token_payload = {}
    # verify token
    try:
        token_payload = jwt.decode(token,
                                   secret,
                                   leeway=timedelta(seconds=30),    # give 30 second leeway on time checks
                                   issuer='auth_server',
                                   algorithms='HS256')
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

    if username is None:
        return token_payload

    if token_payload['sub'] != username:
        abort(403, 'Invalid token subject')

    return token_payload


def require_auth():
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            secret = current_app.config['SECRET_KEY']
            payload = check_token(secret, kwargs['username'])
            kwargs['token'] = payload
            return f(*args, **kwargs)

        return wrapped
    return decorator
