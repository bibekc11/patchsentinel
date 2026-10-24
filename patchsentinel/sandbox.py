"""Best-effort isolation: temp copy, scrubbed env, timeout, Python-level network block.
NOT a hardened sandbox: run only on repositories you own or intentionally vulnerable demo code."""
from __future__ import annotations
import os, shutil, subprocess, sys, tempfile
from pathlib import Path
from typing import Iterable, Tuple

NETBLOCK = '''import socket
def _blocked(*a, **k):
    raise OSError("network disabled by PatchSentinel sandbox")
socket.socket.connect = _blocked
socket.socket.connect_ex = _blocked
socket.create_connection = _blocked
'''
IGNORE = shutil.ignore_patterns(".git", "__pycache__", ".venv", "venv", "node_modules", "*.pyc", ".pytest_cache", ".patchsentinel")


def copy_repo(src: Path) -> Path:
    dst = Path(tempfile.mkdtemp(prefix="ps_repo_")) / "repo"
    shutil.copytree(src, dst, ignore=IGNORE)
    return dst


def _env(repo: Path, extra_path: Path) -> dict:
    keep = {k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "LANG", "LC_ALL")}
    keep.update({"PYTHONPATH": os.pathsep.join([str(extra_path), str(repo)]), "PYTHONDONTWRITEBYTECODE": "1",
                 "HOME": str(extra_path), "PYTHONHASHSEED": "0"})
    return keep


def _netblock_dir() -> Path:
    d = Path(tempfile.mkdtemp(prefix="ps_net_"))
    (d / "sitecustomize.py").write_text(NETBLOCK)
    return d


def run(repo: Path, args: Iterable[str], timeout: int = 60) -> Tuple[int, str]:
    nb = _netblock_dir()
    try:
        proc = subprocess.run([sys.executable, *args], cwd=repo, env=_env(repo, nb), capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout + proc.stderr)[-4000:]
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s"
    finally:
        shutil.rmtree(nb, ignore_errors=True)


def run_pytest(repo: Path, targets=None, timeout: int = 60) -> Tuple[int, str]:
    args = ["-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *(targets or [])]
    return run(repo, args, timeout)


def eval_call(repo: Path, module: str, function: str, args: list, timeout: int = 30) -> Tuple[bool, str]:
    """Run function(*args) in the sandbox and return its repr (used to record baseline behaviour)."""
    code = ("import importlib,json,sys\n"
            f"m=importlib.import_module({module!r})\n"
            f"r=getattr(m,{function!r})(*json.loads({__import__('json').dumps(args)!r}))\n"
            "print('<<PS>>'+repr(r))\n")
    rc, out = run(repo, ["-c", code], timeout)
    if rc != 0 or "<<PS>>" not in out:
        return False, out
    return True, out.split("<<PS>>", 1)[1].splitlines()[0]
