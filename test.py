import ctypes
import faulthandler
import os

import certifi
import google.auth.transport._custom_tls_signer
import google.auth.transport.requests
import requests

faulthandler.enable()

cert_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cert")

# Handling certificates and keys.
ca_cert_file = os.path.join(cert_folder, "ca_cert.pem")
with open(os.path.join(cert_folder, "rsa_cert.pem"), "rb") as f:
    rsa_cert = f.read()
rsa_key_path = os.path.join(cert_folder, "rsa_key.pem")

with open(os.path.join(cert_folder, "ec_cert.pem"), "rb") as f:
    ec_cert = f.read()
ec_key_path = os.path.join(cert_folder, "ec_key.pem")

# Manually set CA cert path to verify local mtls server's cert.
def where():
    return ca_cert_file
certifi.where = where

def get_sign_callback(key_path):
    from cryptography.hazmat.bindings._openssl import ffi
    @ffi.callback("int(unsigned char *sig, size_t *sig_len,const unsigned char *tbs, size_t tbs_len)")
    def sign_callback(sig, sig_len, tbs, tbs_len):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.asymmetric import ec

        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )

        print(sig)
        print(sig_len)
        print(tbs)
        print(tbs_len)
        data = bytes(ffi.buffer(tbs, tbs_len))
        #data = ctypes.string_at(tbs, tbs_len)
        hash = hashes.Hash(hashes.SHA256())
        hash.update(data)
        digest = hash.finalize()

        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=len(digest)),
                hashes.SHA256(),
            )
        else:
            signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        sig_len[0] = len(signature)
        if sig:
            for i in range(len(signature)):
                sig[i] = signature[i]

        return 1

    return sign_callback

def run(cert, key_path):
    session = requests.Session()
    signer = google.auth.transport._custom_tls_signer.CustomTlsSigner(None)
    signer._cert = cert
    callback = get_sign_callback(key_path)
    signer._sign_callback = callback
    adapter = google.auth.transport.requests._MutualTlsOffloadAdapter(None, signer)

    session.mount("https://", adapter)

    r = session.get("https://localhost:3000/foo")
    print(r)

def test_ec():
    run(ec_cert, ec_key_path)

def test_rsa():
    run(rsa_cert, rsa_key_path)

test_rsa()
test_ec()