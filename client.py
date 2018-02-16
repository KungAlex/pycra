import pycra
import requests
import time

# Simple Client with Challenge-Response Authentication (PBKDF2 hashed Passwords stored)


username="kungalex"
password="secret"

response = requests.get('http://localhost:5000/')
time.sleep(1)
print(response.json())

response = requests.post('http://localhost:5000/api/login', json={'username': username})
if response.status_code == 200:
    r=response.json()
    print(r)

    answer = pycra.calculate_answer_for_pbkdf2(r['nonce'], password, algorithm=r['algorithm'], salt=r['salt'],
                                               iterations=r['iterations'])
    print(answer)

    time.sleep(3)

    response = requests.post('http://localhost:5000/api/token', json={'username': username, 'answer': answer})

    if response.status_code == 201:

        r = response.json()
        print(r)


else:
    print(response)

