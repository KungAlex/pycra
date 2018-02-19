from unittest import TestCase
import pbkdf2helper


class User(object):
    """
    My Test User Model
    """

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.nonce = None


class BaseTestClass(TestCase):
    """
    Base test class
    """

    @classmethod
    def setUpClass(cls):
        # 0. Init User Credentials

        # user with password in plaintext
        pwh = pbkdf2helper.encode(algorithm="sha256", password="secret", salt=pbkdf2helper.generate_salt(12), iterations=1000)
        cls.User = User(password=pwh, username="kungalex")
