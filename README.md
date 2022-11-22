## 1. Install dependencies

First create and enable a virtual env:
```
pyenv virtualenv my-env
pyenv local my-env
```

Then install dependencies:
```
git clone https://github.com/arithmetic1728/cryptography.git
cd cryptography
python -m pip install -e .
```

```
python -m pip install -r requirements.txt
```
Note that this will build cryptography library, which may need installation of rust compiler, see [installation guide](https://cryptography.io/en/latest/installation/).


## 2. Run a local mTLS server

Navigate to `./cert` folder, and start an OpenSSL s_server
```
openssl s_server -cert rsa_cert.pem -key rsa_key.pem -CAfile ca_cert.pem -WWW -port 3000 -verify_return_error -Verify 1
```

## 3. Run the test

```
python test.py
```
