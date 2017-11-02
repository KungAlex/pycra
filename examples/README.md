### Usage

##### Simple Flask App with Challenge-Response Authentication (password stored in Plaintext)
run python flask_cra.py

http POST localhost:5000/api/v1.0/login username=kungalex cnonce=abc
pycra.calculate_answer("5cf3e273763f03705ae2e5136cff63618681d48638f2bf545f2dea94113ab2dd","abc", "secret").hexdigest()
http POST localhost:5000/api/v1.0/token username=kungalex answer=549fa395f3b389883a5678a8e3e954xxxx


##### Simple Flask App with Challenge-Response Authentication (PBKDF2 hashed Passwords stored)
run python flask_cra_pbkdf2.py

http POST localhost:5000/api/v1.0/login username=kungalex
pycra.calculate_answer_for_pbkdf2("c45b7d45c017a38da38d00f529f16b1e3e646b6a53c7c6eb696d2cb881f603fe", "abcd", "secret", "sha256", "XqLEjHoDaEKk", 1000).hexdigest()
http POST localhost:5000/api/v1.0/token username=kungalex answer=549fa395f3b389883a5678a8e3e954xxxx