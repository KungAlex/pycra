from pycra.core import create_challenge, calculate_answer, auth_check, calculate_answer_for_pbkdf2
import pbkdf2helper
from pycra.test.base import BaseTestClass


class SimpleLoginTest(BaseTestClass):
    def setUp(self):
        # 0. on Client
        self.clientUser1.cnonce = create_challenge(self.clientUser1)

        # 1. client -> Server POST:{username, cnonce}
        # ... simulation
        self.serverUser1.cnonce = self.clientUser1.cnonce

        # 2. on Server: create challenge
        challenge = create_challenge(self.serverUser1)
        self.serverUser1.nonce = challenge

        # 3. Server -> client  response: {challenge}
        # ... simulation todo verify message
        self.clientUser1.nonce = challenge

    def test_first_auth_with_plain_stored_passwords(self):

        # 4. on Client calculate answer = HMAC(challenge+password)
        response = calculate_answer(self.clientUser1.nonce, self.clientUser1.cnonce,
                                    self.clientUser1.password).hexdigest()

        # 5. client -> Server POST: {response}
        # ... simulation

        # 6. on Server: calculate answer = HMAC(challenge+password) and compare digest(answer, response)
        is_auth, nextnonce = auth_check(self.serverUser1, response)

        self.assertTrue(is_auth)

    def test_second_auth_with_plain_stored_passwords(self):

        # 4. on Client calculate answer = HMAC(challenge+password)
        response = calculate_answer(self.clientUser1.nonce, self.clientUser1.cnonce,
                                    self.clientUser1.password).hexdigest()

        # 5. client -> Server POST: {response}
        # ... simulation

        # 6. on Server: calculate answer = HMAC(challenge+password) and compare digest(answer, response)
        is_auth, nextnonce = auth_check(self.serverUser1, response)

        if is_auth:
            self.serverUser1.nonce = nextnonce

        else:
            self.serverUser1.nonce = None  # nextnonce is the last true answer

        self.assertTrue(is_auth)

        # 7. Server -> client  response: {challenge}
        # ... simulation

        # 8. on Client calculate next answer = HMAC(lastanswer+password)
        response = calculate_answer(response, self.clientUser1.cnonce, self.clientUser1.password).hexdigest()

        # 9. client -> Server POST: {response}
        # ... simulation


        # 10. on Server: calculate answer = HMAC(challenge+password) and compare digest(answer, response)
        is_auth, nextnonce = auth_check(self.serverUser1, response)
        self.assertTrue(is_auth)

    def test_auth_fail(self):

        # 4. on Client calculate answer = HMAC(challenge+password)
        response = calculate_answer(self.clientUser1.nonce, self.clientUser1.cnonce,
                                    self.clientUser1.password).hexdigest()

        # 5. client -> Server POST: {response}
        # ... simulation

        # 6. on Server: calculate answer = HMAC(challenge+password) and compare digest(answer, response)
        is_auth, nextnonce = auth_check(self.serverUser1, response)
        self.serverUser1.nonce = nextnonce
        self.assertTrue(is_auth)

        # 7. client -> Server POST: {repeat same response}
        # ... simulation


        # 8. on Server login again with same answer raise Error
        is_auth, nextnonce = auth_check(self.serverUser1, response)
        self.assertFalse(is_auth)

        response = calculate_answer(self.clientUser1.nonce, self.clientUser1.cnonce,
                                    self.clientUser1.password).hexdigest()

        is_auth, nextnonce = auth_check(self.serverUser1, response)

        self.assertFalse(is_auth)


class PBKDF2LoginTest(BaseTestClass):
    def setUp(self):

        # 0. on Client
        self.clientUser2.cnonce = create_challenge(self.clientUser2)

        # 1. client -> Server POST:{username, cnonce}
        # ... simulation
        self.serverUser2.cnonce = self.clientUser2.cnonce

        # 2. on Server: create challenge
        challenge = create_challenge(self.serverUser2)
        self.serverUser2.nonce = challenge

        # 3. Server -> client  response: {challenge, algorithm, iterations, salt}
        # ... simulation todo verify message
        self.clientUser2.nonce = challenge

    def test_first_auth_with_hashed_passwords(self):

        # 4. on Client calculate answer = HMAC(challenge+password hash)
        algorithm, iterations, salt, h = pbkdf2helper.split(self.serverUser2.password)
        self.assertEqual("sha256", algorithm)
        response = calculate_answer_for_pbkdf2(self.clientUser2.nonce, self.clientUser2.cnonce,
                                               self.clientUser2.password, algorithm, salt, iterations).hexdigest()

        # 5. client -> Server POST: {response}
        # ... simulation

        # 6. on Server: calculate answer = HMAC(challenge+password) and compare digest(answer, response)
        is_auth, nextnonce = auth_check(self.serverUser2, response)
        self.assertTrue(is_auth)

    def test_second_auth_with_hashed_passwords(self):

        # 4. on Client calculate answer = HMAC(challenge+password hash)
        algorithm, iterations, salt, h = pbkdf2helper.split(self.serverUser2.password)
        self.assertEqual("sha256", algorithm)
        response = calculate_answer_for_pbkdf2(self.clientUser2.nonce, self.clientUser2.cnonce,
                                               self.clientUser2.password, algorithm, salt, iterations).hexdigest()

        # 5. client -> Server POST: {response}
        # ... simulation

        # 6. on Server: calculate answer = HMAC(challenge+password) and compare digest(answer, response)
        is_auth, nextnonce = auth_check(self.serverUser2, response)
        if is_auth:
            self.serverUser2.nonce = nextnonce  # nextnonce is the last true answer

        else:
            self.serverUser2.nonce = None
        self.assertTrue(is_auth)

        # 7. Server -> client  response: {challenge, algorithm, iterations, salt}
        # ... simulation

        # 8. on Client calculate next answer = HMAC(lastanswer+password)
        algorithm, iterations, salt, h = pbkdf2helper.split(self.serverUser2.password)
        response = calculate_answer_for_pbkdf2(response, self.clientUser2.cnonce, self.clientUser2.password, algorithm,
                                               salt, iterations).hexdigest()

        # 9. client -> Server POST: {response}
        # ... simulation

        # 10. on Server: calculate answer = HMAC(challenge+password) and compare digest(answer, response)
        is_auth, nextnonce = auth_check(self.serverUser2, response)
        self.assertTrue(is_auth)

    def test_auth_fail_with_hashed_passwords(self):

        # 4. on Client calculate answer = HMAC(challenge+password hash)
        algorithm, iterations, salt, h = pbkdf2helper.split(self.serverUser2.password)
        self.assertEqual("sha256", algorithm)
        response = calculate_answer_for_pbkdf2(self.clientUser2.nonce, self.clientUser2.cnonce,
                                               self.clientUser2.password, algorithm, salt, iterations).hexdigest()

        # 5. client -> Server POST: {response}
        # ... simulation

        # 6. on Server: calculate answer = HMAC(challenge+password) and compare digest(answer, response)
        is_auth, nextnonce = auth_check(self.serverUser2, response)
        if is_auth:
            self.serverUser2.nonce = nextnonce  # nextnonce is the last true answer

        else:
            self.serverUser2.nonce = None
        self.assertTrue(is_auth)

        # 6.2. on Server login again with same answer raise Error
        is_auth, nextnonce = auth_check(self.serverUser2, response)
        self.assertFalse(is_auth)
