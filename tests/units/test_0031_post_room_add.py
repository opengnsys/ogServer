import requests
import unittest

class TestPostRoomAddMethods(unittest.TestCase):

    def setUp(self):
        self.url = 'http://localhost:8888/room/add'
        self.headers = {'Authorization' : '07b3bfe728954619b58f0107ad73acc1'}
        self.full_json = { "center": 0,
                           "name": "classroom11",
                           "netmask": "255.255.255.0",
                           "group": 0,
                           "location": "First floor",
                           "gateway": "192.168.56.1",
                           "ntp": "hora.cica.es",
                           "dns": "1.1.1.1",
                           "remote": True }
        self.minimal_json = { "center": 0,
                              "name": "classroom10",
                              "netmask": "255.255.255.0" }
        self.duplicated_room_json = { "center": 0,
                                      "name": "repeated_room",
                                      "netmask": "255.255.255.0" }

    def test_post(self):
        returned = requests.post(self.url, headers=self.headers,
                                 json=self.full_json)
        self.assertEqual(returned.status_code, 200)

    def test_post_only_required_fields(self):
        returned = requests.post(self.url, headers=self.headers,
                                 json=self.minimal_json)
        self.assertEqual(returned.status_code, 200)

    def test_post_duplicated_room(self):
        requests.post(self.url, headers=self.headers,
                                 json=self.duplicated_room_json)
        returned = requests.post(self.url, headers=self.headers,
                                 json=self.duplicated_room_json)
        self.assertEqual(returned.status_code, 400)

    def test_get(self):
        returned = requests.get(self.url, headers=self.headers)
        self.assertEqual(returned.status_code, 405)

if __name__ == '__main__':
    unittest.main()
