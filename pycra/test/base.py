from unittest import TestCase
import pbkdf2helper


class ClientUser(object):
    """
    My Test Client User Model
    """

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.cnonce = None
        self.psk = None


class ServerUser(object):
    """
    My Test Sever User Model
    """

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.nonce = None
        self.nextnonce = None
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
        cls.serverUser1 = ServerUser(password="secret",
                                     username="kungalex")

        cls.clientUser1 = ClientUser(password="secret",
                                     username="kungalex")


        # user with PBKDF2 hashed password (only on Server)
        pwh = pbkdf2helper.encode("secret", pbkdf2helper.generate_salt(12), 1000)

        cls.serverUser2 = ServerUser(password=pwh,
                                     username="kungalex-with-hashed-pw")

        cls.clientUser2 = ClientUser(password="secret",
                                     username="kungalex-with-hashed-pw")

        psk = pbkdf2helper.generate_salt(12)
        cls.serverUser2.psk = psk
        cls.clientUser2.psk = psk

    @classmethod
    def tearDownClass(cls):
        pass
