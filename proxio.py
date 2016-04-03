#!/usr/bin/env python3

import argparse
import requests
import socket
import sys
import threading
import signal
import os
import pwd, grp


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


def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    """ Source: http://stackoverflow.com/a/2699996/1114687 """

    if os.getuid() != 0:
        # We're not root, so no need to drop privileges
        return

    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)

    # Ensure a very conservative umask
    old_umask = os.umask(0o077)


def handle_connection(conn, addr):
    all_data = b''

    while True:
        data = conn.recv(1024)

        if not data:
            break

        all_data += data

    print('[%s]:%d : %d bytes received' % (addr[0], addr[1], len(all_data)))

    ix_io_url = ix_io_post(all_data)

    print('[%s]:%d : Pasted to %s' % (addr[0], addr[1], ix_io_url))

    conn.sendall(bytearray('%s\n' % ix_io_url, "utf_8"))

    conn.close()
    print('[%s]:%d : Connection closed' % (addr[0], addr[1]))


def start_server(port, host=''):
    print('Starting TCP server on %s:%d...' % (host, port))

    global server_socket

    server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    try:
        server_socket.bind((host, port))

    except OSError as err:
        print('Bind failed: [Errno %d] %s' % (err.errno, err.strerror))
        sys.exit()

    if os.getuid() == 0:
        print('Port bound, dropping privileges...')
        try:
            drop_privileges()

        except Exception as e:
            print('Error while trying to drop privileges: %s\nBetter safe than sorry, so let\'s stop right here.' % e.message)
            sys.exit()

    server_socket.listen(10)
    print('Now listening.')

    while True:
        # wait to accept a connection - blocking call
        conn, addr = server_socket.accept()
        print('[%s]:%d : Connection accepted' % (addr[0], addr[1]))

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
