import os
import subprocess


def lookup_host(host):
    return os.popen(f"echo resolving {host}").read()


def trace_host(host):
    return os.popen(f"echo tracing {host}").read()


def tool_version():
    return subprocess.run(["python3", "--version"], capture_output=True, text=True).returncode
