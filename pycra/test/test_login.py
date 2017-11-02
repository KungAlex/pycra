from pycra.core import create_challenge, calculate_answer, auth_check, calculate_answer_for_pbkdf2
import pbkdf2helper
from pycra.test.base import BaseTestClass


class LoginTest(BaseTestClass):

    def setUp(self):
        pass

    def test_auth_with_plain_stored_passwords(self):

        # 0. on Client
        self.clientUser1.cnonce = create_challenge(self.clientUser1)
        # 1. client -> Server POST:{username, cnonce}
        # ... simulation


        # 2. on Server: create challenge
        self.assertNotEqual(None, self.clientUser1.cnonce)
        self.serverUser1.cnonce = self.clientUser1.cnonce

        challenge = create_challenge(self.serverUser1)

        self.serverUser1.nonce = challenge
        self.assertNotEqual(None, self.serverUser1.nonce)
        # 2.1 pre calculate answer and hash with cnonce


        # 3. Server -> client  response: {challenge}
        # ... simulation

        # 4. on Client calculate answer = HMAC(challenge+password)
        response = calculate_answer(challenge, self.clientUser1.cnonce, self.clientUser1.password)

        # 5. client -> Server POST: {response}
        # ... simulation

        # 6. on Server: calculate answer = HMAC(challenge+password) and compare digest(answer, response)
        is_auth, nextnonce = auth_check(self.serverUser1, response) # 6.1 create new challenge (TODO in core)
        challenge = create_challenge(self.serverUser1)
        self.serverUser1.nonce = challenge
        self.serverUser1.nextnonce = nextnonce # nextnonce is the last true answer

        self.assertTrue(is_auth)


        # 6.2. on Server login again with same answer raise Error
        is_auth, nextnonce = auth_check(self.serverUser1, response)
        self.assertFalse(is_auth)

        # 3. Server -> client  response: {challenge}
        # ... simulation

        # 7. on Client calculate next answer = HMAC(lastanswer+password)
        response = calculate_answer(response, self.clientUser1.cnonce, self.clientUser1.password)

        # 8. client -> Server POST: {response}
        # ... simulation


        # 9. on Server: calculate answer = HMAC(challenge+password) and compare digest(answer, response)
        is_auth, nextnonce = auth_check(self.serverUser1, response)
        self.assertTrue(is_auth)

    def test_auth_with_hashed_passwords(self):

        # 0. on Client
        self.clientUser2.cnonce = create_challenge(self.clientUser2)
        self.serverUser2.cnonce = self.clientUser2.cnonce


        # 1. client -> Server POST:{username, cnonce}
        # ... simulation

        # 2. on Server: create challenge
        challenge = create_challenge(self.serverUser2)
        self.serverUser2.nonce = challenge
        self.assertNotEqual("", self.serverUser2.nonce)
        algorithm, iterations, salt, h = pbkdf2helper.split(self.serverUser2.password)
        self.assertEqual("sha256", algorithm)

        # 3. Server -> client  response: {challenge, algorithm, iterations, salt}
        # ... simulation

        # 4. on Client calculate answer = HMAC(challenge+password hash)

        response = calculate_answer_for_pbkdf2(challenge, self.clientUser2.cnonce, self.clientUser2.password, algorithm, salt, iterations)

        # 5. client -> Server POST: {response}
        # ... simulation

        # 6. on Server: calculate answer = HMAC(challenge+password) and compare digest(answer, response)
        is_auth, nextnonce = auth_check(self.serverUser2, response)
        challenge = create_challenge(self.serverUser2)
        self.serverUser2.nonce = challenge
        self.serverUser2.nextnonce = nextnonce  # nextnonce is the last true answer
        self.assertTrue(is_auth)

        # 6.2. on Server login again with same answer raise Error
        is_auth, nextnonce = auth_check(self.serverUser2, response)
        self.assertFalse(is_auth)

        # 3. Server -> client  response: {challenge, algorithm, iterations, salt}

        # ... simulation

        # 7. on Client calculate next answer = HMAC(lastanswer+password)
        algorithm, iterations, salt, h = pbkdf2helper.split(self.serverUser2.password)
        response = calculate_answer_for_pbkdf2(response, self.clientUser2.cnonce, self.clientUser2.password, algorithm, salt, iterations)


        # 8. client -> Server POST: {response}
        # ... simulation


        # 9. on Server: calculate answer = HMAC(challenge+password) and compare digest(answer, response)
        is_auth, nextnonce = auth_check(self.serverUser2, response)
        self.assertTrue(is_auth)

