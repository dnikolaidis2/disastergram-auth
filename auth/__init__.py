from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from flask_apispec.extension import FlaskApiSpec
# from kazoo.client import KazooClient
# # from kazoo.interfaces.IHandler import timeout_exception
# from kazoo.exceptions import *
from os import environ, path

db = SQLAlchemy()
ma = Marshmallow()
bc = Bcrypt()
docs = FlaskApiSpec()


def create_app(test_config=None):
    # Get info from hosts file
    # hosts_lines = open('/etc/hosts', 'r').readlines()
    # container_ip, container_id = hosts_lines[-1].strip('\n').split('\t', 1)

    # create the app configuration
    app = Flask(__name__,
                instance_path=environ.get('FLASK_APP_INSTANCE', '/user/src/app/instance'))  # instance path

    app.config.from_mapping(
        SQLALCHEMY_DATABASE_URI='postgresql+psycopg2://postgres:disastergram@auth-db/postgres',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        AUTH_LEEWAY=int(environ.get('AUTH_LEEWAY', '30')),  # leeway in seconds
    )

    if test_config is None:
        # load the instance config if it exists, when not testing
        app.config.from_pyfile(path.join(app.instance_path, 'config.py'), silent=True)
    else:
        app.config.from_mapping(test_config)

    if not app.testing:
        app.config.update({
            'APISPEC_SPEC': APISpec(
                title='disastergram-auth',
                version='v1',
                openapi_version='2.0',
                plugins=[MarshmallowPlugin()],
            ),
            'APISPEC_SWAGGER_URL': '/auth/spec',
            'APISPEC_SWAGGER_UI_URL': '/auth/spec-ui',
        })

    # INIT

    db.init_app(app)
    ma.init_app(app)
    bc.init_app(app)

    if not app.testing:
        docs.init_app(app)

    # for some reason when not in development
    # this call fails /shrug
    if app.env == 'development':
        from auth import models
        models.init_db(app)

    from auth import auth

    app.register_blueprint(auth.bp)

    if not app.testing:
        docs.register(auth.user_register, blueprint='auth')

        docs.register(auth.user_read, blueprint='auth')
        docs.register(auth.user_replace, blueprint='auth')
        docs.register(auth.user_update, blueprint='auth')
        docs.register(auth.user_del, blueprint='auth')

        docs.register(auth.user_read_id, blueprint='auth')
        docs.register(auth.user_replace_id, blueprint='auth')
        docs.register(auth.user_update_id, blueprint='auth')
        docs.register(auth.user_del_id, blueprint='auth')

        docs.register(auth.login, blueprint='auth')
        docs.register(auth.refresh_token, blueprint='auth')
        docs.register(auth.logout, blueprint='auth')

        docs.register(auth.pub_key, blueprint='auth')

    return app
