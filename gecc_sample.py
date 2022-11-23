import faulthandler
import os
from sys import platform

from google.auth.transport import requests
import google.auth

faulthandler.enable()

creds, _ = google.auth.default()
project = "sijunliu-dca-test"

current_folder = os.path.dirname(os.path.abspath(__file__))

def get_enterprise_cert_file_path():
    if platform == "win32":
        return os.path.join(current_folder, "enterprise_cert.json")
    elif platform == "darwin":
        return os.path.join(current_folder, "enterprise_cert.json")
    return os.path.join(current_folder, "ecp_linux_amd64", "enterprise_cert.json")

def run_sample():
    file_path = get_enterprise_cert_file_path()
    adapter = requests._MutualTlsOffloadAdapter(file_path)
    authed_session = requests.AuthorizedSession(creds)
    authed_session.mount("https://", adapter)
    response = authed_session.request("GET", f"https://pubsub.mtls.googleapis.com/v1/projects/{project}/topics")
    print(response)
    print(response.text)

if __name__ == "__main__":
    run_sample()
    run_sample()