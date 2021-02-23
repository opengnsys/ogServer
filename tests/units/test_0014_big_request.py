import requests
import unittest

MAX_REQ_SIZE = 131072

class TestBigRequest(unittest.TestCase):

    def setUp(self):
        self.url = 'http://localhost:8888/clients'
        self.data = 'X' * MAX_REQ_SIZE

    def test_post(self):
        returned = requests.post(self.url, data=self.data)
        self.assertEqual(returned.status_code, 413)

if __name__ == '__main__':
    unittest.main()
