"""One strict HTTP opener for all credential-bearing EG and adapter requests.

urllib's default redirect handler copies Authorization/X-Evaluation-Key into
requests to other origins. Never forward credentials to a redirect target.
"""
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, build_opener


class _DenyRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise HTTPError(request.full_url, code,
                        "AUTHENTICATED_HTTP_REDIRECT_DENIED", headers, fp)


_OPENER = build_opener(_DenyRedirect())


def urlopen(request, *, timeout=10):
    """Drop ALL redirects; callers explicitly validate their first URL."""
    return _OPENER.open(request, timeout=timeout)
