from instance.config import PUBLIC_KEY
import json, os

def test_pubkey(client):
	response = client.get('/auth/pubkey')
	assert response.status_code == 200
	resp_json = json.loads(response.data) 
	assert resp_json == {'public_key': PUBLIC_KEY.decode('utf-8')}