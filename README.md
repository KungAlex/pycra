#### Python Challenge Response Authentication with PBKDF2 support

install: 
    
    run pip install pycra
    
Functions for use on Server:

+ create_challenge
+ auth_check 
+ sign_message 

Functions for use on Client:

+ create_challenge
+ verify_message
+ calculate_answer 
+ calculate_answer_for_pbkdf2




Server Example:
    
    cd examples/server
    python flask_cra.py
    
Client Example:
    
    cd examples/client
    python client.py


Copyright (c) 2017 Alexander Kleinschmidt (Kungalex)

MIT License