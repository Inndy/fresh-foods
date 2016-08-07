#!/usr/bin/env python3
import warnings
import functools
import socket
import ssl
import urllib.parse

__version__ = '0.0.1'

"""
Inndy's simple HTTP client

A demo for writing a http client.

[!] This program requires Python/3.5 or higher to run
[!] This client DOES NOT perform a certificate checking, it's vulnerable to
    MITM attack, DO NOT USE THIS IN REAL WORLD.
"""

class SecurityWarning(UserWarning):
    pass

class HTTPResponse(object):
    def __init__(self, status_code, headers, content):
        self.status_code = status_code
        self.headers = headers
        self.content = content

    @property
    def body(self):
        return self.content

    def __repr__(self):
        return '<HTTPResonse status_code=%d>' % self.status_code

def tcp_connect(host, port, use_ssl=False):
    soc = socket.socket()
    soc.connect((host, port))
    if use_ssl:
        warnings.warn('This https client is vulnerable to man-in-the-middle ' +
                      'attack because of the lack of certificate checking',
                      SecurityWarning)
        soc = ssl.wrap_socket(soc)
    return soc

def read_all(soc):
    data = b''
    while True:
        tmp = soc.recv(1000000)
        if not tmp: break
        data += tmp
    return data

def request(method, url, body=None, headers={}):
    # determine protocol (use SSL or not)
    if url.startswith('http://'):
        ssl = False
        url = url[len('http://'):]
    elif url.startswith('https://'):
        ssl = True
        url = url[len('https://'):]
    else:
        ssl = False

    # determine host and port
    if '/' in url:
        host, url = url.split('/', 1)
        url = '/' + url
    else:
        host, url = url, '/'

    if ':' in host:
        host, port = host.split(':', 1)
        port = int(port, 10)
    else:  # default port is 80 for plain http, 443 for https
        host, port = host, 80 if not ssl else 443

    if body and (type(body) is dict or hasattr(body, '__iter__')):
            body = urllib.parse.urlencode(body)

    final_header = {
        'Host': '%s:%d' % (host, port) if port != 80 else host,
        'User-Agent': 'inndy/%s' % __version__,
        'Content-Length': len(body) if body else None,
        'Connection': 'close'
    }

    final_header.update(headers)

    header = ''.join(
        '%s: %s\r\n' % (key, value)
        for key, value in final_header.items()
        if value
    )

    request_line = '%s %s HTTP/1.1\r\n' % (method, url)

    soc = tcp_connect(host, port, ssl)
    soc.sendall(request_line.encode())
    soc.sendall(header.encode())
    soc.sendall(b'\r\n')  # end of headers

    if body:
        soc.sendall(body if type(body) is bytes else body.encode())

    response = soc.recv(1000000)
    while b'\r\n\r\n' not in response:
        data = soc.recv(1000000)
        if not data: break
        response += data

    print(response)

    status_line, response = response.split(b'\r\n', 1)
    response_header, body = response.split(b'\r\n\r\n', 1)

    http_ver, status_code, status_text = status_line.decode().split(maxsplit=2)
    status_code = int(status_code, 10)

    response_header = {
        key.decode(): value.decode()
        for key, value in (
            i.split(b': ', 1)
            for i in response_header.split(b'\r\n')
        )
    }

    if 'TRANSFER-ENCODING' in ( h.upper() for h in response_header ):
        warnings.warn('Transfer-Encoding detected, response body may be wired')
        return HTTPResponse(status_code, response_header, body)

    body_length = int(response_header.get('Content-Length', '0'), 10)
    if not body_length:
        warnings.warn('Can not find `Content-Length` in response headers')
        body += read_all(soc)
        return HTTPResponse(status_code, response_header, body)

    while len(body) < body_length:
        body += soc.recv(1000000)

    return HTTPResponse(status_code, response_header, body[:body_length])

get    = functools.partial(request, 'GET')
post   = functools.partial(request, 'POST')
put    = functools.partial(request, 'PUT')
patch  = functools.partial(request, 'PATCH')
delete = functools.partial(request, 'DELETE')

if __name__ == '__main__':
    def test(response):
        print(response)
        print(response.headers)
        print(response.content)

    test(get('http://codepad.org'))
    test(get('https://google.com/'))
    try:
        test(post('http://localhost:8000/index.php?a=b',
            {'Hello': 'World', '測試': '!@#$'}))
    except:
        pass
