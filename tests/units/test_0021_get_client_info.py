import requests
import unittest

class TestGetClientInfoMethods(unittest.TestCase):

    def setUp(self):
        self.url = 'http://localhost:8888/client/info'
        self.headers = {'Authorization' : '07b3bfe728954619b58f0107ad73acc1'}
        self.json = { "client": ["192.168.56.12"] }

    def test_get(self):
        returned = requests.get(self.url, headers=self.headers, json=self.json)
        self.assertEqual(returned.status_code, 200)

if __name__ == '__main__':
    unittest.main()