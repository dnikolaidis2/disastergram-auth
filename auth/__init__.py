from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from flask_apispec.extension import FlaskApiSpec
from kazoo.client import KazooClient, KazooRetry
from auth.zookeeper import AuthZoo
from datetime import timedelta
from os import environ, path

db = SQLAlchemy()
mi = Migrate()
ma = Marshmallow()
bc = Bcrypt()
docs = FlaskApiSpec()
zk = None


def create_app(test_config=None):
    # create the app configuration
    app = Flask(__name__,
                instance_path=environ.get('FLASK_APP_INSTANCE', '/user/src/app/instance'))  # instance path

    app.config.from_mapping(
        POSTGRES_HOST=environ.get('POSTGRES_HOST', ''),
        POSTGRES_USER=environ.get('POSTGRES_USER', ''),
        POSTGRES_DATABASE=environ.get('POSTGRES_DATABASE', environ.get('POSTGRES_USER', '')),
        POSTGRES_PASSWORD=environ.get('POSTGRES_PASSWORD', ''),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        AUTH_LEEWAY=timedelta(seconds=int(environ.get('AUTH_LEEWAY', '30'))),  # leeway in seconds
        BASEURL=environ.get('BASEURL', ''),
        DOCKER_HOST=environ.get('DOCKER_HOST', ''),
        DOCKER_BASEURL='http://{}'.format(environ.get('DOCKER_HOST', '')),
        TOKEN_ISSUER=environ.get('JWT_ISSUER', environ.get('BASEURL', 'auth')),
        ZOOKEEPER_CONNECTION_STR=environ.get('ZOOKEEPER_CONNECTION_STR', 'zoo1,zoo2,zoo3'),
    )

    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://{}:{}@{}/{}'.format(app.config['POSTGRES_USER'],
                                                                                       app.config['POSTGRES_PASSWORD'],
                                                                                       app.config['POSTGRES_HOST'],
                                                                                       app.config['POSTGRES_DATABASE'])

    if test_config is None:
        # load the instance config if it exists, when not testing
        app.config.from_pyfile(path.join(app.instance_path, 'config.py'), silent=True)
    else:
        app.config.from_mapping(test_config)

    if not app.testing:
        if app.config.get('POSTGRES_HOST') == '':
            raise Exception('No postgres database host was provided. '
                            'POSTGRES_HOST environment variable cannot be omitted')

        if app.config.get('POSTGRES_USER') == '':
            raise Exception('No postgres database user was provided. '
                            'POSTGRES_USER environment variable cannot be omitted')

        if app.config.get('POSTGRES_PASSWORD') == '':
            raise Exception('No postgres database user password was provided. '
                            'POSTGRES_PASSWORD environment variable cannot be omitted')

        if app.config.get('BASEURL') == '':
            raise Exception('No service base url was provided. '
                            'BASEURL environment variable cannot be omitted')

        if app.config.get('DOCKER_HOST') == '':
            raise Exception('No network host within docker was provided. '
                            'DOCKER_HOST environment variable cannot be omitted')

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

        # Only do zookeeper for non testing configs for now
        znode_data = {
            'TOKEN_ISSUER': app.config['TOKEN_ISSUER'],
            'BASEURL': app.config['BASEURL'],
            'DOCKER_HOST': app.config['DOCKER_HOST'],
            'DOCKER_BASEURL': app.config['DOCKER_BASEURL'],
            'PUBLIC_KEY': app.config['PUBLIC_KEY'].decode('utf-8')
        }

        global zk
        zk = AuthZoo(KazooClient(app.config['ZOOKEEPER_CONNECTION_STR'],
                                 connection_retry=KazooRetry(max_tries=-1),
                                 logger=app.logger),
                     znode_data)

    # INIT

    db.init_app(app)
    mi.init_app(app, db,
                directory=environ.get('FLASK_APP_MIGRATIONS', 'migrations'))
    ma.init_app(app)
    bc.init_app(app)

    if not app.testing:
        docs.init_app(app)

    # for some reason when not in development
    # this call fails ¯\_(ツ)_/¯.
    # Probably some kind of problem with
    # threading and prefork.
    if app.env == 'development':
        from auth import models
        models.init_db(app)

    from auth import service

    app.register_blueprint(service.bp)

    if not app.testing:
        docs.register(service.user_register, blueprint='auth')

        docs.register(service.user_read, blueprint='auth')
        docs.register(service.user_replace, blueprint='auth')
        docs.register(service.user_update, blueprint='auth')
        docs.register(service.user_del, blueprint='auth')

        docs.register(service.user_read_id, blueprint='auth')
        docs.register(service.user_replace_id, blueprint='auth')
        docs.register(service.user_update_id, blueprint='auth')
        docs.register(service.user_del_id, blueprint='auth')

        docs.register(service.login, blueprint='auth')
        docs.register(service.refresh_token, blueprint='auth')
        docs.register(service.logout, blueprint='auth')

        docs.register(service.pub_key, blueprint='auth')

    return app
