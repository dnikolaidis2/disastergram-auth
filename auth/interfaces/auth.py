import requests
import urllib.parse

class Auth:

    def __init__(self, baseurl):
        self._baseurl = baseurl

    def register(self, username, password):
        payload = {
            'username':  username,
            'password': password,
        }

        return requests.post(urllib.parse.urljoin(self._baseurl, 'register'), json=payload)

    def read_user_by_username(self, username, token=None):
        if token is not None:
            payload = {
                'token':  token
            }

            return requests.get(urllib.parse.urljoin(self._baseurl, 'user/{}'.format(username)),
                                params=payload)
        else:
            return requests.get(urllib.parse.urljoin(self._baseurl, 'user/{}'.format(username)))

    def replace_user_by_username(self, username, new_username, new_password, token):
        payload = {
            'token': token,
            'new_username':  new_username,
            'new_password': new_password,
        }

        return requests.put(urllib.parse.urljoin(self._baseurl, 'user/{}'.format(username)),
                            json=payload)

    def update_user_by_username(self, username, new_username=None, new_password=None, token):
        if new_password is None and new_username is None:
            return None
        payload = {
            'token': token
        }

        if new_username is not None:
            payload['new_username'] = new_username

        if new_password is not None:
            payload['new_password'] = new_password

        return requests.patch(urllib.parse.urljoin(self._baseurl, 'user/{}'.format(username)),
                              json=payload)

    def delete_user_by_username(self, username, token):
        payload = {
            'token': token
        }

        return requests.delete(urllib.parse.urljoin(self._baseurl, 'user/{}'.format(username)),
                              json=payload)

    def read_user_by_id(self, user_id, token=None):
        if token is not None:
            payload = {
                'token':  token
            }

            return requests.get(urllib.parse.urljoin(self._baseurl, 'user/{}'.format(user_id)),
                                params=payload)
        else:
            return requests.get(urllib.parse.urljoin(self._baseurl, 'user/{}'.format(user_id)))

    def replace_user_by_id(self, user_id, new_username, new_password, token):
        payload = {
            'token': token,
            'new_username':  new_username,
            'new_password': new_password,
        }

        return requests.put(urllib.parse.urljoin(self._baseurl, 'user/{}'.format(user_id)),
                            json=payload)

    def update_user_by_id(self, user_id, new_username=None, new_password=None, token):
        if new_password is None and new_username is None:
            return None
        payload = {
            'token': token
        }

        if new_username is not None:
            payload['new_username'] = new_username

        if new_password is not None:
            payload['new_password'] = new_password

        return requests.patch(urllib.parse.urljoin(self._baseurl, 'user/{}'.format(user_id)),
                              json=payload)

    def delete_user_by_id(self, user_id, token):
        payload = {
            'token': token
        }

        return requests.delete(urllib.parse.urljoin(self._baseurl, 'user/{}'.format(user_id)),
                              json=payload)

    def login(self, username, password):
        payload = {
            'username': username,
            'password': password,
        }

        return requests.post(urllib.parse.urljoin(self._baseurl, 'login'),
                             json=payload)

    def refresh_token(self, token):
        payload = {
            'token': token,
        }

        return requests.put(urllib.parse.urljoin(self._baseurl, 'refresh'),
                            json=payload)

    def logout(self, token):
        payload = {
            'token': token,
        }

        return requests.delete(urllib.parse.urljoin(self._baseurl, 'refresh'),
                               json=payload)

    def get_public_key(self):
        return requests.get(urllib.parse.urljoin(self._baseurl, 'pubkey'))
