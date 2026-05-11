#!/usr/bin/env python3
"""
ipscromp - Python client for the ipscromp firewall authentication protocol.

Usage: ipscromp.py [-1] [-d] [-l user] [-p pass] [-i alt_ip] [user@]host[:port] [...]
"""

import getpass
import hashlib
import os
import socket
import sys

DEFAULT_HOST    = "labrat.lexington.ibm.com"
DEFAULT_PORT    = 2002
DEFAULT_SERVICE = "ipscromp"
BUFFSIZE        = 4096

debug = False


def dbg(msg):
    if debug:
        print(f"DEBUG: {msg}", file=sys.stderr)


def hash_auth(version, s):
    data = s.encode()
    if version == 1:
        return hashlib.md5(data).hexdigest()
    return hashlib.sha1(data).hexdigest()


def parse_host(spec):
    """Parse [user@]host[:port].  Bare IPv6 addresses (multiple colons) are
    not split on ':' — use host:port only when there is exactly one colon."""
    user = None
    if '@' in spec:
        user, spec = spec.split('@', 1)

    first = spec.find(':')
    last  = spec.rfind(':')
    port  = None
    if first != -1 and first == last:
        host_part, port_str = spec[:first], spec[first + 1:]
        try:
            port = int(port_str)
        except ValueError:
            try:
                port = socket.getservbyname(port_str, 'tcp')
            except OSError:
                pass
        spec = host_part

    return user, spec, port


def resolve_port(port):
    if port is not None:
        return port
    try:
        return socket.getservbyname(DEFAULT_SERVICE, 'tcp')
    except OSError:
        return DEFAULT_PORT


def connect_ipscrompd(spec, default_user, password, version, alt_ip):
    user, host, port = parse_host(spec)
    if user is None:
        user = default_user
    port = resolve_port(port)

    dbg(f"connecting to {host}:{port} as {user}")

    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        print(f"Unable to resolve '{host}': {e}", file=sys.stderr)
        return 1

    sock = None
    for af, socktype, proto, _canon, sockaddr in infos:
        dbg(f"trying {sockaddr}")
        s = None
        try:
            s = socket.socket(af, socktype, proto)
            s.connect(sockaddr)
            sock = s
            break
        except OSError:
            if s:
                s.close()

    if sock is None:
        print(f"Unable to connect to {host}:{port}", file=sys.stderr)
        return 1

    def send(msg):
        dbg(f"sending '{msg.rstrip()}'")
        sock.sendall(msg.encode())

    def recv():
        data = sock.recv(BUFFSIZE).decode().strip()
        dbg(f"received '{data}'")
        return data

    send(f"USER {user} {version}\n")

    response = recv()
    if not response.startswith("AUTH "):
        print(f"Server responded incorrectly: '{response}'")
        sock.close()
        return 1

    challenge = response[5:]

    if alt_ip is None:
        auth_str = f"{user}:{challenge}:{password}"
        h = hash_auth(version, auth_str)
        send(f"PERMIT {h}\n")
    else:
        auth_str = f"{user}:{alt_ip}:{challenge}:{password}"
        h = hash_auth(version, auth_str)
        send(f"IPERMIT {alt_ip} {h}\n")

    response = recv()
    sock.close()

    if not response.startswith("OK "):
        print(f"Server reports an error: '{response}'")
        return 1

    print(response)
    return 0


def main():
    global debug

    version     = 2
    user        = getpass.getuser()
    password    = None
    alt_ip      = None
    hosts       = []

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == '-1':
            version = 1
        elif a == '-d':
            debug = True
        elif a in ('-l', '-u'):
            i += 1; user = args[i]
        elif a == '-p':
            i += 1; password = args[i]
        elif a == '-i':
            i += 1; alt_ip = args[i]
        elif a in ('-h', '--help'):
            print(f"Usage: {sys.argv[0]} [-1] [-d] [-l user] [-p pass] [-i ip] "
                  f"[user@]host[:port] [...]")
            sys.exit(0)
        elif a.startswith('-'):
            print(f"Unknown option: {a}", file=sys.stderr)
            sys.exit(1)
        else:
            hosts.append(a)
        i += 1

    if alt_ip is not None and version < 2:
        print("WARNING: Alternative IP unsupported with old protocol", file=sys.stderr)

    if alt_ip is not None:
        try:
            infos = socket.getaddrinfo(alt_ip, None, socket.AF_UNSPEC)
            alt_ip = infos[0][4][0]
        except socket.gaierror:
            print(f"Cannot resolve '{alt_ip}' to an IP address", file=sys.stderr)
            sys.exit(1)

    if password is None:
        envpass = os.environ.get('IPSCROMP_PASS')
        if envpass:
            password = envpass
        else:
            password = getpass.getpass("Your password: ")

    if not hosts:
        hosts = [DEFAULT_HOST]

    rc = 0
    for host in hosts:
        rc += connect_ipscrompd(host, user, password, version, alt_ip)
    sys.exit(rc)


if __name__ == '__main__':
    main()
