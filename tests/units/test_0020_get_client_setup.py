import requests
import unittest

class TestGetClientSetupMethods(unittest.TestCase):

    def setUp(self):
        self.url = 'http://localhost:8888/client/setup'
        self.headers = {'Authorization' : '07b3bfe728954619b58f0107ad73acc1'}
        self.json = { 'client': ['192.168.56.12'] }

    def test_get(self):
        returned = requests.get(self.url, headers=self.headers, json=self.json)
        self.assertEqual(returned.status_code, 200)

    def test_get_without_data(self):
        returned = requests.get(self.url, headers=self.headers)
        self.assertEqual(returned.status_code, 400)

    def test_malformed_payload(self):
        returned = requests.get(self.url, headers=self.headers, json={'malformed':['192.168.56.12']})
        self.assertEqual(returned.status_code, 400)


if __name__ == '__main__':
    unittest.main()
