# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring

from urllib.parse import urlparse

from werkzeug.serving import WSGIRequestHandler

from searx import settings


class ReverseProxyPathFix:
    '''Wrap the application in this middleware and configure the
    front-end server to add these headers, to let you quietly bind
    this to a URL other than / and to an HTTP scheme that is
    different than what is used locally.
    '''

    # pylint: disable=too-few-public-methods

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app
        self.script_name = None
        self.scheme = None
        self.server = None

        if settings['server']['base_url']:
            base_url = urlparse(settings['server']['base_url'])
            self.script_name = base_url.path
            if self.script_name.endswith('/'):
                self.script_name = self.script_name[:-1]
            self.scheme = base_url.scheme
            self.server = base_url.netloc

    def __call__(self, environ, start_response):
        script_name = self.script_name or environ.get('HTTP_X_SCRIPT_NAME', '')
        if script_name:
            environ['SCRIPT_NAME'] = script_name
            path_info = environ['PATH_INFO']
            if path_info.startswith(script_name):
                environ['PATH_INFO'] = path_info[len(script_name):]

        scheme = self.scheme or environ.get('HTTP_X_SCHEME') or environ.get('HTTP_X_FORWARDED_PROTO')
        if scheme:
            environ['wsgi.url_scheme'] = scheme

        server = self.server or environ.get('HTTP_X_FORWARDED_HOST', '')
        if server:
            environ['HTTP_HOST'] = server
        return self.wsgi_app(environ, start_response)


class SecurityMiddleware:
    '''Defense-in-depth controls at the WSGI boundary.'''

    MAX_CONTENT_LENGTH = 1024 * 1024
    MAX_QUERY_STRING_LENGTH = 8192
    SECURITY_HEADERS = (
        ('X-Content-Type-Options', 'nosniff'),
        ('X-Frame-Options', 'DENY'),
        ('Referrer-Policy', 'no-referrer'),
        ('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()'),
        ('Cross-Origin-Opener-Policy', 'same-origin'),
        ('Cross-Origin-Resource-Policy', 'same-origin'),
        ('Content-Security-Policy', "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' https:; font-src 'self' data: https:"),
    )

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    @staticmethod
    def _reject(start_response, status, message):
        body = message.encode('utf-8')
        headers = [
            ('Content-Type', 'text/plain; charset=utf-8'),
            ('Content-Length', str(len(body))),
            ('Cache-Control', 'no-store'),
            *SecurityMiddleware.SECURITY_HEADERS,
        ]
        start_response(status, headers)
        return [body]

    def __call__(self, environ, start_response):
        method = environ.get('REQUEST_METHOD', 'GET').upper()
        if method == 'TRACE':
            return self._reject(start_response, '405 Method Not Allowed', 'Method not allowed')

        if len(environ.get('QUERY_STRING', '')) > self.MAX_QUERY_STRING_LENGTH:
            return self._reject(start_response, '414 URI Too Long', 'Request URI too long')

        try:
            content_length = int(environ.get('CONTENT_LENGTH') or 0)
        except ValueError:
            return self._reject(start_response, '400 Bad Request', 'Invalid Content-Length')
        if content_length > self.MAX_CONTENT_LENGTH:
            return self._reject(start_response, '413 Request Entity Too Large', 'Request entity too large')

        def secure_start_response(status, headers, exc_info=None):
            existing = {name.lower() for name, _ in headers}
            headers = list(headers)
            for name, value in self.SECURITY_HEADERS:
                if name.lower() not in existing:
                    headers.append((name, value))
            if environ.get('wsgi.url_scheme', '').lower() == 'https':
                headers.append(('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'))
            return start_response(status, headers, exc_info)

        return self.wsgi_app(environ, secure_start_response)


def patch_application(app):
    WSGIRequestHandler.protocol_version = "HTTP/{}".format(settings['server']['http_protocol_version'])
    app.wsgi_app = ReverseProxyPathFix(app.wsgi_app)
    app.wsgi_app = SecurityMiddleware(app.wsgi_app)
