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
        self.cnonce = None
        self.psk = None


class BaseTestClass(TestCase):
    """
    Base test class
    """

    @classmethod
    def setUpClass(cls):
        # 0. Init User Credentials

        # user with password in plaintext
        cls.serverUser1 = User(password="secret",
                                     username="kungalex")

        cls.clientUser1 = User(password="secret",
                                     username="kungalex")


        # user with PBKDF2 hashed password (only on Server)
        pwh = pbkdf2helper.encode("secret", pbkdf2helper.generate_salt(12), 1000)

        cls.serverUser2 = User(password=pwh,
                                     username="kungalex-with-hashed-pw")

        cls.clientUser2 = User(password="secret",
                                     username="kungalex-with-hashed-pw")

        psk = pbkdf2helper.generate_salt(12)
        cls.serverUser2.psk = psk
        cls.clientUser2.psk = psk

    @classmethod
    def tearDownClass(cls):
        pass
