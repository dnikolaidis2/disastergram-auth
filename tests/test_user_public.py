import json, pytest
from auth import db

def test_public_get(client, test_users):
	for user in test_users:
		response = client.get('/auth/user/{}'.format(user['id']))
		assert response.status_code == 200

		resp_json = json.loads(response.data)
		assert resp_json == user

		response = client.get('/auth/user/{}'.format(user['username']))
		assert response.status_code == 200

		resp_json = json.loads(response.data)
		assert resp_json == user
