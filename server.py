from fastapi import FastAPI, Form
from typing import Annotated
import uvicorn
import os
import sys
import json
import bcrypt
import jwt
import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pymongo
from pymongo import MongoClient
from bson.objectid import ObjectId
from pydantic import BaseModel

app = FastAPI()

client = MongoClient()
db = client.zvms

privateKey = RSA.import_key(open("rsa_private_key.pem", "rb").read())
publicKey = RSA.import_key(open("rsa_public_key.pem", "rb").read())

def rsa_decrypt(ciphertext):
    cipher = PKCS1_OAEP.new(privateKey)
    decrypt_text = cipher.decrypt(bytes.fromhex(ciphertext))
    return decrypt_text.decode("utf8")

class AuthData(BaseModel):
    userid: str
    credit: str

@app.post('/auth')
def authorize(userid: Annotated[str, Form()], credit: Annotated[str, Form()]):
    global db
    print(credit)
    loginCredit = json.loads(rsa_decrypt(credit))
    print(loginCredit)
    collection = db.users
    item = collection.find_one({"_id": ObjectId(userid)})
    print(item, loginCredit)
    password = item['password']
    print(bytes(loginCredit['password'].encode("utf8")))
    print(bytes(password.encode("utf8")))
    if bcrypt.checkpw(bytes(loginCredit['password'].encode("utf8")), bytes(password.encode("utf8"))):
        payload = {
          "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=60),
          "iat": datetime.datetime.utcnow(),
          "sub": str(item["_id"]),
          "scope": "access_token",
          "type": "long-term",
          "permission": item["position"]
        }
        return jwt.encode(payload, '279618cb36a7947d714cfcee8d7a2564bee8452e4c295fd7b1f7aacd55ab4bf9', algorithm="HS256")
    else:
        return "Invalid password"

@app.get('/public_cert')
def get_public_cert():
    return publicKey.export_key().decode("utf8")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0:8000")
