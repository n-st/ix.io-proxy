#!/usr/bin/env python3

import argparse
import requests


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


def main():
    parser = argparse.ArgumentParser(description='Accepts data on a TCP port and forwards it to http://ix.io/')
    parser.add_argument('-p', '--port', nargs=1, type=portnumber, required=True)

    args = parser.parse_args()

if __name__ == "__main__":
    main()

