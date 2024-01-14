import bcrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import jwt
import json
import datetime

print(jwt.__version__)

login = {
  "password": "regdfpbijkl",
  "time": 1705155788943, 
}

credit = json.dumps(login)

privateKey = RSA.import_key(open("rsa_private_key.pem", "rb").read())
publicKey = RSA.import_key(open("rsa_public_key.pem", "rb").read())
jwtPrivateKey = open("ecc-private-key.pem", "r").read()


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def check_password(password, hashed):
    return bcrypt.checkpw(password.encode("utf-8"), hashed)


pwd = "114514"
hashed = hash_password(pwd)


def rsa_encrypt(plaintext):
    cipher = PKCS1_OAEP.new(publicKey)
    encrypt_text = cipher.encrypt(bytes(plaintext.encode("utf8")))
    return encrypt_text.hex()


def rsa_decrypt(ciphertext):
    cipher = PKCS1_OAEP.new(privateKey)
    decrypt_text = cipher.decrypt(bytes.fromhex(ciphertext))
    return decrypt_text.decode("utf8")


def jwt_encode(id: str):
    payload = {
      "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=60),
      "iat": datetime.datetime.utcnow(),
      "sub": id,
      "scope": "access_token",
      "type": "long-term"
    }
    return jwt.encode(payload, '279618cb36a7947d714cfcee8d7a2564bee8452e4c295fd7b1f7aacd55ab4bf9', algorithm="HS256")


def jwt_decode(token):
    return jwt.decode(token, '279618cb36a7947d714cfcee8d7a2564bee8452e4c295fd7b1f7aacd55ab4bf9', algorithms=["HS256"], verify=True)


encrypted = rsa_encrypt(credit)

print(encrypted)

decrypted = rsa_decrypt(encrypted)

print(decrypted)

# creditloaded = json.loads(decrypted)

print(decrypted)

creditload = json.loads(decrypted)

print(creditload)

bcrypted = hash_password(creditload['password'])

# bcrypted = hash_password(decrypted)

token = jwt_encode('65a2a1331cd86b19b3291f8e')

print(token)

result = jwt_decode(token)

print(result)

print(bcrypted)
