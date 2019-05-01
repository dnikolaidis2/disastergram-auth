import pytest, json
from auth.models import User


@pytest.mark.parametrize(('username', 'password', 'response', 'status_code'), (
	('', '', {"error": "field username cannot be empty"}, 400),
	('test', '', {"error": "field password cannot be empty"}, 400),
	('', 'test', {"error": "field username cannot be empty"}, 400),
	('test', 'test', {"username": "test"}, 201),
	('test', 'test', {"error": "Username \'test\' has already been taken"}, 400),
))
def test_register(auth, app, username, password, response, status_code):
	resp = auth.register_user(username, password)
	# print(resp.data)
	assert resp.status_code == status_code
	if response != {}:
		resp_json = json.loads(resp.data)
		if (response.get('username') is not None) and (response.get('id') is None):
			with app.app_context():
				user = User.query.filter(User.username == username).one_or_none()
				assert user is not None
				response['id'] = str(user.id.int)

		assert resp_json == response

	