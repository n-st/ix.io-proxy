#!/usr/bin/env python3

import argparse
import requests
import socket
import sys
import threading
import signal


server_socket = None


def ix_io_post(content):
    payload = {'f:0': content}
    r = requests.post("http://ix.io/", data=payload)
    return r.text.strip()


def portnumber(value):
    try:
        ivalue = int(value)
    except ValueError:
         raise argparse.ArgumentTypeError("'%s' is not a valid port number (should be an integer between 1 and 65535)" % value)

    if not 1 <= ivalue <= 65535:
         raise argparse.ArgumentTypeError("'%s' is not a valid port number (should be an integer between 1 and 65535)" % value)

    return ivalue


def handle_connection(conn, addr):
    all_data = b''

    while True:
        data = conn.recv(1024)

        if not data:
            break

        all_data += data

    print("%d bytes received" % len(all_data))

    conn.close()


def start_server(port, host=''):
    print('Starting TCP server on %s:%d...' % (host, port))

    global server_socket

    server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    try:
        server_socket.bind((host, port))

    except OSError as err:
        print('Bind failed: [Errno %d] %s' % (err.errno, err.strerror))
        sys.exit()

    server_socket.listen(10)
    print('Now listening.')

    while True:
        # wait to accept a connection - blocking call
        conn, addr = server_socket.accept()
        print('Connected with ' + addr[0] + ':' + str(addr[1]))

        threading.Thread(
                target=handle_connection,
                args=(conn, addr),
            ).start()

    server_socket.close()
    server_socket = None


def exit_gracefully(signal_number, stack_frame):
    print('Received signal %d, preparing to exit.' % signal_number)

    global server_socket

    if server_socket is not None:
        print('Closing server socket.')
        server_socket.close()

    print('Terminating now.')

    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    parser = argparse.ArgumentParser(description='Accepts data on a TCP port and forwards it to http://ix.io/')
    parser.add_argument('-p', '--port', type=portnumber, required=True)

    args = parser.parse_args()

    start_server(args.port)

if __name__ == "__main__":
    main()