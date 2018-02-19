from flask import Flask, jsonify, request
from flask import abort
import pbkdf2helper

from pycra import create_challenge, auth_check

app = Flask(__name__)

# Simple Flask App with Challenge-Response Authentication (PBKDF2 hashed Passwords stored)


class User(object):
    """
    My Test User Model
    """

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.nonce = None


@app.route('/', methods=['GET'])
def index():
    response = {

        'description': 'Hallo from Flask Pycra Example',
        'loginUrl': 'POST /api/login'
    }

    return jsonify(response), 200


@app.route('/api/login', methods=['POST'])
def login():
    if not request.json:
        abort(400)

    if not 'username' in request.json:
        abort(400)

    # todo get user form DB
    if request.json['username'] != testuser.username:
        abort(405, "user not found")

    testuser.nonce = create_challenge()
    algorithm, iterations, salt, h = pbkdf2helper.split(testuser.password)

    response = {

        'description': 'This is your Challenge',
        'nonce': testuser.nonce,
        'algorithm': algorithm,
        'salt': salt,
        'iterations': iterations,
        'tokenUrl': "POST /api/token"
    }

    return jsonify(response), 200


@app.route('/api/token', methods=['POST'])
def get_token():
    if not request.json:
        abort(400)

    if not ('answer' and 'username') in request.json:
        abort(400)

    # todo get user form DB
    if request.json['username'] != testuser.username:
        abort(405, "user not found")

    if testuser.nonce is None:
        abort(400, "please use first /api/login")

    is_auth = auth_check(testuser.nonce, testuser.password, request.json['answer'])

    if is_auth:

        response = {

            'description': 'Welcome',
            'token': "ey.example.Token",
            'exp': "value"

        }

        return jsonify(response), 201

    else:

        testuser.nonce = create_challenge()
        algorithm, iterations, salt, h = pbkdf2helper.split(testuser.password)

        response = {

            'description': 'Wrong answer! There is your new Challenge',
            'nonce': testuser.nonce,
            'algorithm': algorithm,
            'salt': salt,
            'iterations': iterations,
            'tokenUrl': "POST /api/token"
        }

        return jsonify(response), 405


if __name__ == '__main__':
    pwh = pbkdf2helper.encode(algorithm="sha256", password="secret", salt=pbkdf2helper.generate_salt(12),
                              iterations=1000)

    testuser = User(password=pwh, username="kungalex")

    print(str(testuser.username) + " : " + str(testuser.password))
    app.run()
