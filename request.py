import requests
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import datetime
import json
import urllib

publicKey = RSA.import_key(open("rsa_public_key.pem", "rb").read())

def rsa_encrypt(plaintext):
    cipher = PKCS1_OAEP.new(publicKey)
    encrypt_text = cipher.encrypt(bytes(plaintext.encode("utf8")))
    return encrypt_text.hex()


def generate_login_credit():
    _id = '65a0bd12e0ffb1863b9a48ca'
    password = '20230616'
    stamp =  datetime.datetime.utcnow()
    payload = {
        "password": password,
        "time": stamp.timestamp(),
    }
    credit = rsa_encrypt(json.dumps(payload))
    return _id, credit


def request():
    url = 'http://127.0.0.1:8000/auth'
    _id, credit = generate_login_credit()
    payload = {
        "userid": _id,
        "credit": credit,
    }
    r = requests.post(url, data=payload)
    print(r.text)

request()