from pycra.core import create_challenge, calculate_answer, auth_check
import pbkdf2helper
from pycra.test.base import BaseTestClass


class SimpleLoginTest(BaseTestClass):
    def setUp(self):
        self.User.nonce = create_challenge()

    def test_auth(self):

        response = calculate_answer(self.User.nonce, self.User.password)

        is_auth= auth_check(self.User.nonce, self.User.password, response)

        self.assertTrue(is_auth)