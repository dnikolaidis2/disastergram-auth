import os, sys

print(sys.path.append(os.getcwd()))

from auth import create_app, db
from auth.models import User, init_db, UserSchema
from instance.config import *
import pytest, uuid


class AuthActions():
	def __init__(self, client):
		self._client = client
	
	def register_user(self, username='test', password='test'):
		return self._client.post('/auth/register',
			json={
				'username': username,
				'password': password
			})

	def get_user(self, user_identifier, token=None):
		if token is None:
			return self._client.get(
					'auth/user/{}'.format(user_identifier)
				)
		else:
			return self._client.get(
					'auth/user/{}?token={}'.format(user_identifier, token)
				)

	def create_token(self, username='test', password='test'):
		return self._client.post('/auth/login',
			json={
				'username': username,
				'password': password
			})

	def refresh_token(self, token):
		return self._client.put('/auth/refresh',
			json={
				'token': token
			})


@pytest.fixture
def test_users(app):
	users_data = None
	with app.app_context():
		users = []

		for x in range(1,20):
			user = User(username='test_{}_{}'.format(uuid.uuid4().hex, x), password='test{}'.format(x))
			db.session.add(user)
			users.append(user)

		db.session.commit()
		users_data = UserSchema().dump(users, many=True)

		return users_data.data


@pytest.fixture
def app():
	app = create_app({
		'TESTING': True,
	    'SQLALCHEMY_DATABASE_URI': 'postgresql+psycopg2://postgres:disastergram@test-db/postgres',
	    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
	    'ENV': 'testing',
	    'PUBLIC_KEY': PUBLIC_KEY,
	    'PRIVATE_KEY': PRIVATE_KEY,
	    'SECRET_KEY':  SECRET_KEY,
	})
	
	init_db(app)

	yield app


@pytest.fixture
def client(app):
	return app.test_client()


@pytest.fixture
def pubkey(client):
	return client.get('/auth/pubkey')


@pytest.fixture
def auth(client):
	return AuthActions(client)
