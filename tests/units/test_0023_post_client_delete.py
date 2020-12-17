import requests
import unittest

class TestPostClientDeleteMethods(unittest.TestCase):

    def setUp(self):
        self.url = 'http://localhost:8888/client/delete'
        self.headers = {'Authorization' : '07b3bfe728954619b58f0107ad73acc1'}
        self.json = { "clients": ["192.168.56.30"] }

    def test_post(self):
        returned = requests.post(self.url, headers=self.headers, json=self.json)
        self.assertEqual(returned.status_code, 200)

    def test_post_no_payload(self):
        returned = requests.post(self.url, headers=self.headers, json=None)
        self.assertEqual(returned.status_code, 400)

    def test_post_malformed_payload(self):
        returned = requests.post(self.url, headers=self.headers, json={})
        self.assertEqual(returned.status_code, 400)


if __name__ == '__main__':
    unittest.main()
