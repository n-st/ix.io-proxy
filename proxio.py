#!/usr/bin/env python3

import argparse
import requests
import socket
import sys
import threading
import signal
import os
import pwd, grp
import logging
import logging.handlers


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

    logging.getLogger('[%s]:%d' % (addr[0], addr[1])).info('%d bytes received' % len(all_data))

    ix_io_url = ix_io_post(all_data)

    logging.getLogger('[%s]:%d' % (addr[0], addr[1])).info('Pasted to %s' % ix_io_url)

    conn.sendall(bytearray('%s\n' % ix_io_url, "utf_8"))

    conn.close()
    logging.getLogger('[%s]:%d' % (addr[0], addr[1])).info('Connection closed')


def start_server(port, host=''):
    logging.getLogger('proxio').info('Starting TCP server on %s:%d...' % (host, port))

    global server_socket

    server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    try:
        server_socket.bind((host, port))

    except OSError as err:
        logging.getLogger('proxio').error('Bind failed: [Errno %d] %s' % (err.errno, err.strerror))
        sys.exit(err.errno)

    if os.getuid() == 0:
        logging.getLogger('proxio').info('Port bound, dropping privileges...')
        try:
            drop_privileges()

        except Exception as e:
            logging.getLogger('proxio').error('Error while trying to drop privileges: \'%s\'. Better safe than sorry, so let\'s stop right here.' % str(e))
            try:
                sys.exit(e.errno)
            except AttributeError:
                # The exception didn't have an errno
                sys.exit(-1)

    server_socket.listen(10)
    logging.getLogger('proxio').info('Now listening.')

    while True:
        # wait to accept a connection - blocking call
        conn, addr = server_socket.accept()
        logging.getLogger('[%s]:%d' % (addr[0], addr[1])).info('Connection accepted')

        threading.Thread(
                target=handle_connection,
                args=(conn, addr),
            ).start()

    server_socket.close()
    server_socket = None


def exit_gracefully(signal_number, stack_frame):
    logging.getLogger('proxio').info('Received signal %d, preparing to exit.' % signal_number)

    global server_socket

    if server_socket is not None:
        logging.getLogger('proxio').info('Closing server socket.')
        server_socket.close()

    logging.getLogger('proxio').info('Terminating now.')

    sys.exit(0)


def configure_logging(to_syslog=False, verbose=False):
    class NoWarningOrHigherFilter(logging.Filter):
        def filter(self, record):
            return not record.levelno > logging.WARNING

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if to_syslog:
        log_formatter = logging.Formatter('%(levelname)s - %(name)s: %(message)s')

        syslog_logger = logging.handlers.SysLogHandler('/dev/log')
        syslog_logger.setFormatter(log_formatter)

        if verbose:
            syslog_logger.setLevel(logging.INFO)
        else:
            syslog_logger.setLevel(logging.WARNING)

        root_logger.addHandler(syslog_logger)

    else:
        log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s', '%b %e %H:%M:%S')

        stderr_logger = logging.StreamHandler(sys.stderr)
        stderr_logger.setLevel(logging.WARNING)
        stderr_logger.setFormatter(log_formatter)
        root_logger.addHandler(stderr_logger)

        if verbose:
            stdout_logger = logging.StreamHandler(sys.stdout)
            stdout_logger.setLevel(logging.INFO)
            stdout_logger.setFormatter(log_formatter)
            stdout_logger.addFilter(NoWarningOrHigherFilter())
            root_logger.addHandler(stdout_logger)


def main():
    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    parser = argparse.ArgumentParser(description='Accepts data on a TCP port and forwards it to http://ix.io/')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--syslog', action='store_true', help='Send log messages to syslog instead of stdout/stderr')
    parser.add_argument('-p', '--port', type=portnumber, required=True)

    args = parser.parse_args()

    configure_logging(args.syslog, args.verbose)

    start_server(args.port)

if __name__ == "__main__":
    main()
