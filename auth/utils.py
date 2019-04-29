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
                abort(400, 'REST API call is not json')

            return f(*args, **kwargs)

        return wrapped
    return decorator


def check_token(pub_key, token=None):
    if pub_key is None:
        abort(500, "Server error occurred while processing request")

    actual_token = None
    if token is None:
        if request.method == 'GET':
            # check if token was sent with request
            if request.args == {}:
                abort(400, 'Token is not part of request')

            # check if token is not empty
            actual_token = request.args.get('token')
            if actual_token is None:
                abort(400, 'Token field is empty')
        else:
            # check json data
            if request.json.get('token') is None:
                abort(400, 'Token is not part of request form')

            actual_token = request.json.get('token')
    else:
        actual_token = token

    token_payload = None
    # verify token
    try:
        token_payload = jwt.decode(actual_token,
                                   pub_key,
                                   leeway=timedelta(days=30),    # give 30 second leeway on time checks
                                   issuer='auth_server',
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

    return token_payload


def require_auth(pub_key="PUBLIC_KEY"):
    if not callable(pub_key):
        pub_key = lambda: current_app.config.get('PUBLIC_KEY')

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            payload = check_token(pub_key())
            kwargs['token_payload'] = payload
            return f(*args, **kwargs)

        return wrapped
    return decorator
