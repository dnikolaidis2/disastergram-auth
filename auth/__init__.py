from flask import Flask
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


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
        app.config.from_pyfile('config.py', silent=False)
    else:
        app.config.from_mapping(test_config)

    @app.route('/')
    def hello():
        return 'Hello, world!'

    return app
