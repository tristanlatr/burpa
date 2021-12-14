#!/usr/bin/env python3
# Run a server with a broken certificate.

CERT_FILE = "https://raw.githubusercontent.com/chromium/badssl.com/master/certs/src/crt/ca-edellroot.crt"
KEY_FILE = "https://raw.githubusercontent.com/chromium/badssl.com/master/certs/src/key/ca-edellroot.key"

from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import tempfile
import requests
import pathlib
import os

if __name__ == "__main__":

    httpd = HTTPServer(('localhost', 4443), BaseHTTPRequestHandler)

    temp_dir = pathlib.Path(tempfile.gettempdir())
    temp_file = temp_dir / "expired-cert-for-testing.pem"

    with temp_file.open('w', encoding='utf-8') as cert:
        cert.write(requests.get(CERT_FILE).text)

    temp_key = temp_dir / "expired-key-for-testing.pem"

    with temp_key.open('w', encoding='utf-8') as cert:
        cert.write(requests.get(KEY_FILE).text)

    httpd.socket = ssl.wrap_socket(httpd.socket, 
            certfile=temp_file.as_posix(), keyfile=temp_key.as_posix(), server_side=True)

    try:
        httpd.serve_forever()
    finally:
        os.remove(temp_key)
        os.remove(temp_file)