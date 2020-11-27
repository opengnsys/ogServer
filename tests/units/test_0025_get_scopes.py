import requests
import unittest

class TestGetScopesMethods(unittest.TestCase):

    def setUp(self):
        self.url = 'http://localhost:8888/scopes'
        self.headers = {'Authorization' : '07b3bfe728954619b58f0107ad73acc1'}
        self.json = None

    def test_get(self):
        returned = requests.get(self.url, headers=self.headers, json=self.json)
        self.assertEqual(returned.status_code, 200)

    def test_empty_payload(self):
        returned = requests.get(self.url, headers=self.headers, json={})
        self.assertEqual(returned.status_code, 400)

    def test_malformed_payload(self):
        returned = requests.get(self.url, headers=self.headers, json={ 'client': ['192.168.56.11'] })
        self.assertEqual(returned.status_code, 400)


if __name__ == '__main__':
    unittest.main()