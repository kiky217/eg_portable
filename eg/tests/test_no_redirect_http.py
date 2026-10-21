"""Credential-bearing HTTP clients must never forward secrets on redirects."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request

import pytest

from tools.no_redirect_http import urlopen


@pytest.mark.parametrize("secret_header",["Authorization","X-Evaluation-Key"])
def test_real_redirect_never_forwards_api_keys(secret_header):
    leaked=[]
    class Sink(BaseHTTPRequestHandler):
        def do_GET(self):
            leaked.append(dict(self.headers))
            self.send_response(200);self.end_headers()
        def log_message(self,*args):pass
    target=ThreadingHTTPServer(("127.0.0.1",0),Sink)
    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location",f"http://127.0.0.1:{target.server_port}/steal")
            self.end_headers()
        def log_message(self,*args):pass
    origin=ThreadingHTTPServer(("127.0.0.1",0),Redirect)
    threads=[Thread(target=server.serve_forever,daemon=True) for server in (origin,target)]
    for thread in threads:thread.start()
    try:
        request=Request(f"http://127.0.0.1:{origin.server_port}/original",
                        headers={secret_header:"secret-must-not-leak"})
        with pytest.raises(HTTPError,match="AUTHENTICATED_HTTP_REDIRECT_DENIED"):
            with urlopen(request,timeout=3):
                pytest.fail("Redirect incorrectly accepted")
        assert leaked==[]
    finally:
        for server in (origin,target):
            server.shutdown();server.server_close()
        for thread in threads:thread.join(timeout=3)
