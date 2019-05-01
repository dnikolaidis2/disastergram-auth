import os, sys

print(sys.path.append(os.getcwd()))

from auth import create_app
import json

def test_config():
	assert not create_app().testing
	assert create_app({'TESTING': True}).testing

def test_hello(client):
	response = client.get('/auth/')
	assert response.status_code == 200

	resp_json = json.loads(response.data)
	assert resp_json == {'status': 'OK'}