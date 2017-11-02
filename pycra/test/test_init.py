import pbkdf2helper
from pycra.test.base import BaseTestClass


class InitTest(BaseTestClass):

    def test_init_plain_passwords(self):
        self.assertEqual(self.serverUser1.username, self.clientUser1.username)
        self.assertEqual(self.serverUser1.password, self.clientUser1.password)

    def test_init_hashed_passwords(self):
        self.assertEqual(self.serverUser2.username, self.clientUser2.username)
        self.assertNotEqual(self.serverUser2.password, self.clientUser2.password)

        algorithm, iterations, salt, h = pbkdf2helper.split(self.serverUser2.password)
        self.assertEqual("sha256", algorithm)
