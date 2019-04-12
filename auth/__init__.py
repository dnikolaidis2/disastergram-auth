from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow

db = SQLAlchemy()
ma = Marshmallow()
bc = Bcrypt()


def create_app(test_config=None):
    # create the app configuration
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='temp',
        SQLALCHEMY_DATABASE_URI='postgresql+psycopg2://postgres:1234@db/postgres',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    if test_config is None:
        # load the instance config if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)

    # INIT

    db.init_app(app)
    ma.init_app(app)
    bc.init_app(app)

    from auth import models
    models.init_db(app)

    from auth import auth

    app.register_blueprint(auth.bp)

    return app
