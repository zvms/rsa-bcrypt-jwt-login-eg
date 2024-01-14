# rsa-bcrypt-jwt-login-eg

The Example of RSA + Bcrypt + JWT Login

## Setup

### Keys

You can generate RSA key pair by using `openssl` command. By the way, I have already written a generator script for you.

```bash
./generate_key.sh
```

### Dependencies

Because I don't know how to properly use `pip` and `conda`, you may install these packages:

```bash
pip install fastapi uvicorn[standart] PyJWT pymongo pythoncryptodome bcrypt
```

### MongoDB

You should run a local `mongodb` server with `zvms.users` through the declaration file in [zvms4-frontend](https://github.com/zvms/zvms4-frontend)

## Run

### The Server

```bash
uvicorn server:app --reload
```

### The Test Client

You can run `request.py` to test it.

```bash
python request.py
```

### Only the Encryption

I wrote a encrypt demo in `cert.py`

## License

Under the [MIT License](./LICENSE)

7086cmd.