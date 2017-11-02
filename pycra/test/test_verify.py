from pycra.test.base import BaseTestClass
from pycra.core import sign_message, verify_message, create_challenge
import pbkdf2helper


class VerifyTest(BaseTestClass):

    def setUp(self):

        cnonce = create_challenge(self.clientUser1)

        self.clientUser1.cnonce=cnonce
        self.serverUser1.cnonce=cnonce

        psk = pbkdf2helper.generate_salt(12)
        self.serverUser1.psk = psk
        self.clientUser1.psk = psk

    def test_sign_and_verify_message(self):
        msg = "Hallo world"

        h = sign_message(msg, self.serverUser1.psk, self.serverUser1.cnonce)
        check = verify_message(msg, self.clientUser1.psk, self.clientUser1.cnonce, h)
        self.assertTrue(check)



