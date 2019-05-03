from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from flask_apispec.extension import FlaskApiSpec
from datetime import timedelta
# from kazoo.client import KazooClient
# # from kazoo.interfaces.IHandler import timeout_exception
# from kazoo.exceptions import *
from os import environ, path

db = SQLAlchemy()
mi = Migrate()
ma = Marshmallow()
bc = Bcrypt()
docs = FlaskApiSpec()
# zk = None


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
        AUTH_LEEWAY=timedelta(seconds=int(environ.get('AUTH_LEEWAY', '30'))),  # leeway in seconds
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
    mi.init_app(app,
                db,
                directory=environ.get('FLASK_APP_MIGRATIONS', 'migrations'))
    ma.init_app(app)
    bc.init_app(app)

    if not app.testing:
        docs.init_app(app)

    # TODO load previous client_id for reconnect
    # zk = KazooClient(hosts='zoo1:2181,zoo2:2181,zoo3:2181',
    #                  logger=app.logger)
    # TODO save client_id for later reconnect

    # for some reason when not in development
    # this call fails /shrug
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

    # zk.start()
    #
    # try:
    #     app.logger.info(zk.client_id)
    #
    #     auth = zk.exists('/auth')
    #
    #     auth_number = app.logger.info(auth.children_count)
    #     zk.create("/auth/{}".format(auth_number), ephemeral=True, makepath=True)
    # except ZookeeperError:
    #     # if the server returns a non-zero error code.
    #     pass

    return app
