import requests
import unittest

class TestGetSoftwareMethods(unittest.TestCase):

    def setUp(self):
        self.url = 'http://localhost:8888/software'
        self.headers = {'Authorization' : '07b3bfe728954619b58f0107ad73acc1'}
        self.json = { 'client' : [ '192.168.2.1' ],
                      'disk' : 1,
                      'partition': 1 }

    def test_get(self):
        returned = requests.get(self.url, headers=self.headers, json=self.json)
        self.assertEqual(returned.status_code, 200)

    def test_no_payload(self):
        returned = requests.get(self.url, headers=self.headers, json=None)
        self.assertEqual(returned.status_code, 400)

    def test_malformed_payload(self):
        for parameter in self.json:
            malformed_payload = self.json.copy()
            malformed_payload.pop(parameter)
            returned = requests.pogetst(self.url,
                                     headers=self.headers,
                                     json=malformed_payload)
            self.assertEqual(returned.status_code, 400)


if __name__ == '__main__':
    unittest.main()
