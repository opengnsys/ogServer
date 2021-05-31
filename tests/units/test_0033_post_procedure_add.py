import requests
import unittest

class TestPostProcedureAddMethods(unittest.TestCase):

    def setUp(self):
        self.url = 'http://localhost:8888/procedure/add'
        self.headers = {'Authorization' : '07b3bfe728954619b58f0107ad73acc1'}
        self.full_json = { "center": "1",
                           "name": "procedure1",
                           "description": "procedure test" }
        self.minimal_json = { "center": "1",
                              "name": "procedure2" }
        self.duplicated_procedure_json = { "center": "1",
                                           "name": "repeated_procedure" }

    def test_post(self):
        returned = requests.post(self.url, headers=self.headers,
                                 json=self.full_json)
        self.assertEqual(returned.status_code, 200)

    def test_post_only_required_fields(self):
        returned = requests.post(self.url, headers=self.headers,
                                 json=self.minimal_json)
        self.assertEqual(returned.status_code, 200)

    def test_post_duplicated_procedure(self):
        requests.post(self.url, headers=self.headers,
                                 json=self.duplicated_procedure_json)
        returned = requests.post(self.url, headers=self.headers,
                                 json=self.duplicated_procedure_json)
        self.assertEqual(returned.status_code, 400)

    def test_get(self):
        returned = requests.get(self.url, headers=self.headers)
        self.assertEqual(returned.status_code, 405)

if __name__ == '__main__':
    unittest.main()
