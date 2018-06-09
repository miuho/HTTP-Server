# HTTP-Server

Implementation of HTTP 1.1 web server (RFC 2616) with HTTPS via TLS protocol (RFC 2818) and common gateway interface (RFC 3875).

Author: HingOn Miu <hmiu@andrew.cmu.edu>

src/server.c



./server 9000 8000 server.log server.lock static_site cgi/wsgi_wrapper.py k.key c.crt

Running the echo server requires 8 arguments, the http and https port number
that the server will be listening for incoming connection, the uri for the
log file and lock file the server will write to, the path to the static sites
for the server to serve, the path for wrapper of the Flask application, and
the private key and public certificate for SSL development.

