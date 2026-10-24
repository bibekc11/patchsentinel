import os

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "reports")


def read_report(name):
    with open(os.path.join(BASE, name)) as fh:
        return fh.read()


def load_template(name):
    with open(os.path.join(BASE, name)) as fh:
        return fh.read().upper()
