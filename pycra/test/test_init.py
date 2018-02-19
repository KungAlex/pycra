import pbkdf2helper
from pycra.test.base import BaseTestClass


class InitTest(BaseTestClass):

    def test_init_hashed_passwords(self):
        self.assertEqual(self.User.username, self.User.username)
        self.assertNotEqual('secret', self.User.password)

        algorithm, iterations, salt, h = pbkdf2helper.split(self.User.password)
        self.assertEqual("sha256", algorithm)
