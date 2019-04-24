from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from flask_apispec.extension import FlaskApiSpec
from os import environ

isinstance_path = ''

db = SQLAlchemy()
ma = Marshmallow()
bc = Bcrypt()
docs = FlaskApiSpec()


def create_app(test_config=None):
    # Get environment variables
    instance_path = environ.get('FLASK_APP_INSTANCE', '/user/src/app/instance')
    flask_env = environ.get('FLASK_ENV', 'deployment')

    # create the app configuration
    app = Flask(__name__, instance_path=instance_path)
    app.config.from_mapping(
        SQLALCHEMY_DATABASE_URI='postgresql+psycopg2://postgres:disastergram@auth-db/postgres',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    if test_config is None:
        # load the instance config if it exists, when not testing
        app.config.from_pyfile(instance_path + '/config.py', silent=True)
    else:
        app.config.from_mapping(test_config)

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
    docs.init_app(app)

    # for some reason when not in development
    # this call fails /shrug
    if flask_env == 'development':
        from auth import models
        models.init_db(app)

    from auth import auth

    app.register_blueprint(auth.bp)

    docs.register(auth.user_register, blueprint='auth')
    docs.register(auth.pub_key, blueprint='auth')
    docs.register(auth.user_read, blueprint='auth')
    docs.register(auth.user_replace, blueprint='auth')
    docs.register(auth.login, blueprint='auth')
    docs.register(auth.refresh_token, blueprint='auth')
    docs.register(auth.logout, blueprint='auth')

    return app
