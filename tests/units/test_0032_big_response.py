import subprocess
import requests
import unittest
import tempfile

class TestBigResponse(unittest.TestCase):

    def setUp(self):
        self.url = 'http://localhost:8888/scopes'
        self.headers = {'Authorization' : '07b3bfe728954619b58f0107ad73acc1'}
        self.query = tempfile.NamedTemporaryFile()
        self.query.write(b'INSERT INTO centros (nombrecentro, identidad, '
                         + b'comentarios, directorio) VALUES '
                         + b'("Center", 1, "", ""),' * 5000
                         + b'("Center", 1, "", "");')

    def test_get(self):
        subprocess.run('mysql --default-character-set=utf8 test-db < '
                       + self.query.name, shell=True)
        returned = requests.get(self.url, headers=self.headers)
        subprocess.run('mysql --default-character-set=utf8 test-db '
                       '< config/basic_data.sql', shell=True)
        self.assertEqual(returned.status_code, 400)

if __name__ == '__main__':
    unittest.main()
