from flask import Flask, jsonify, request
from flask import abort
import pbkdf2helper

from pycra import create_challenge, auth_check, sign_message

app = Flask(__name__)


class User(object):
    """
    My Test User Model
    """

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.nonce = None
        self.nextnonce = None
        self.cnonce = None
        self.psk = None


@app.route('/', methods=['GET'])
def index():
    response = {

        'description': 'Hallo from Flask-cra',
        'loginUrl': 'POST /api/v1.0/login',
        'params': '{username, cnonce}'

    }

    return jsonify(response), 200


@app.route('/api/v1.0/login', methods=['POST'])
def login():
    if not request.json:
        abort(400)

    if not ('cnonce' and 'username') in request.json:
        abort(400)

    if request.json['username'] != testuser.username:
        abort(405, "user not found")

    testuser.cnonce = request.json["cnonce"]
    testuser.nonce = create_challenge(testuser)
    algorithm, iterations, salt, h = pbkdf2helper.split(testuser.password)

    response = {

        'description': 'This is your Challenge',
        'username': testuser.username,
        'nonce': testuser.nonce,
        'algorithm': algorithm,
        'salt': salt,
        'iterations': iterations,
        'tokenUrl': "POST /api/v1.0/token",
        'hmac': sign_message(testuser.nonce, testuser.psk, testuser.cnonce)

    }

    return jsonify(response), 200


@app.route('/api/v1.0/token', methods=['POST'])
def get_token():
    if not request.json:
        abort(400)

    if not ('answer' and 'username') in request.json:
        abort(400)

    if request.json['username'] != testuser.username:
        abort(405, "user not found")

    if (testuser.nonce and testuser.cnonce) is None:
        abort(400, "please use first /api/v1.0/login")

    is_auth, answer = auth_check(testuser, request.json['answer'])
    challenge = create_challenge(testuser)
    testuser.nonce = challenge

    if is_auth:
        testuser.nextnonce = answer  # nextnonce is the last true answer
        response = {

            'description': 'Welcome',
            'token': "ey.example.Token",
            'exp': "value"

        }

        return jsonify(response), 201

    else:
        testuser.nextnonce = None
        testuser.cnonce = None

        testuser.nonce = create_challenge(testuser)
        response = {

            'description': 'Wrong answer! There is your new Challenge',
            'username': testuser.username,
            'nonce': testuser.nonce,

        }

        return jsonify(response), 405


if __name__ == '__main__':
    pwh = pbkdf2helper.encode("secret", pbkdf2helper.generate_salt(12), 1000)
    testuser = User(password=pwh, username="kungalex")
    testuser.psk = pbkdf2helper.generate_salt(8)

    print(str(testuser.username) + " : " + str(testuser.password) + " : " + str(testuser.psk))
    app.run()
