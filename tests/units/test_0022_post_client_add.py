import requests
import unittest

class TestPostClientAddMethods(unittest.TestCase):

    def setUp(self):
        self.url = 'http://localhost:8888/client/add'
        self.headers = {'Authorization' : '07b3bfe728954619b58f0107ad73acc1'}
        self.json = { 'boot' :"19pxeADMIN",
                      "center": 0,
                      "hardware_id": 0,
                       "id": 2,
                       "ip": "192.168.56.13",
                       "livedir": "ogLive",
                       "mac": "0800270E6512",
                       "maintenance": True,
                       "name": "pc12",
                       "netdriver": "generic",
                       "netiface": "eth1",
                       "netmask": "255.255.255.0",
                       "remote": False,
                       "repo_id": 1,
                       "room": 1,
                       "serial_number": "" }


    def test_post(self):
        returned = requests.post(self.url, headers=self.headers, json=self.json)
        self.assertEqual(returned.status_code, 200)

    def test_post_no_payload(self):
        returned = requests.post(self.url, headers=self.headers, json=None)
        self.assertEqual(returned.status_code, 400)

    def test_post_malformed_payload(self):
        returned = requests.post(self.url, headers=self.headers, json={'boot' :"19pxeADMIN",#
                      "center": 0,
                      "hardware_id": 0,
                       "id": 2,
                       "ip": "192.168.56.13",
                       "livedir": "ogLive",
                       "mac": "0800270E6512",
                       "maintenance": True,
                       "name": "pc12",
                       "netdriver": "generic",
                       "netiface": "eth1",
                       "netmask": "255.255.255.0",
                       "remote": False,
                       "repo_id": 1,
                       "room": 1,
                       "serial_number": ""})
        self.assertEqual(returned.status_code, 400)

if __name__ == '__main__':
    unittest.main()
