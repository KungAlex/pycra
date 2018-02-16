#### Python Challenge Response Authentication with PBKDF2 support

install:
    
    run pip install pycra


#### Flask Server Example:
    
    python server.py
    
#### Client Example:
    
    python client.py


#### Terminal Usage:

    http POST localhost:5000/api/v1.0/login username=kungalex

    >>> import pycra
    >>> pycra.calculate_answer_for_pbkdf2("c45b7d45c017a38da38d00f529f16b1e3e646b6a53c7c6eb696d2cb881f603fe", "secret", "sha256", "XqLEjHoDaEKk", 1000).hexdigest()


    http POST localhost:5000/api/v1.0/token username=kungalex answer=549fa395f3b389883a5678a8e3e954xxxx


Copyright (c) 2017 Alexander Kleinschmidt (Kungalex)

MIT License