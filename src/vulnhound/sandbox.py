"""Isolation core for ``vulnhound prove``: run a short Python PoC with network off.

Invariant: a PoC is NEVER executed unconfined. If no real sandbox can be set up,
``run_sandboxed`` returns ``backend="none", available=False`` and runs nothing; the
caller should then mark the finding "unverified".

Backends (best first):

* ``docker``  - ``docker run --network=none`` with memory/pids/cpu limits, read-only root,
  all capabilities dropped, no-new-privileges. Needs a reachable daemon and a local
  Python image (``VULNHOUND_SANDBOX_IMAGE``, default ``python:3.12-slim``; pulled once,
  with a short timeout, if absent).
* ``unshare`` - Linux user+mount+pid+net namespaces (util-linux ``unshare``). A launcher
  stub builds a fresh tmpfs root, bind-mounts the interpreter and ``read_only_paths``
  read-only and ``workdir`` read-write, ``pivot_root``s into it, remounts the root
  read-only, enters a nested user namespace as an unprivileged uid with no capabilities
  and ``no_new_privs``, applies POSIX rlimits, then ``exec``s the command. Loopback is
  left DOWN in the fresh netns, so there is no network at all.

Setup failures (mount denied, no userns, ...) make a backend *unavailable*; they never
degrade to running without confinement.
"""

from __future__ import annotations

import functools
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

__all__ = ["SandboxResult", "available_backends", "run_sandboxed"]

DOCKER_IMAGE_ENV = "VULNHOUND_SANDBOX_IMAGE"
DEFAULT_IMAGE = "python:3.12-slim"
_MAX_OUTPUT = 1_000_000  # bytes kept per stream; the rest is drained and dropped
_SANDBOX_PATH = "/usr/local/bin:/usr/bin:/bin"
_PY_NAMES = ("python", "python3")


@dataclass
class SandboxResult:
    backend: str  # "docker" | "unshare" | "none"
    available: bool  # True if a real sandbox ran the command
    exit_code: int | None  # process exit code, None if not run / killed pre-exec
    stdout: str
    stderr: str
    timed_out: bool
    killed: bool  # killed by a limit (mem/cpu/time/pids)
    reason: str | None  # human note: why unavailable, or why killed
    duration_s: float


def _unavailable(reason: str, backend: str = "none") -> SandboxResult:
    return SandboxResult(backend, False, None, "", "", False, False, reason, 0.0)


# --------------------------------------------------------------------------- helpers


def _drain(stream, sink: list[bytes]) -> None:
    kept = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            return
        if kept < _MAX_OUTPUT:
            sink.append(chunk[: _MAX_OUTPUT - kept])
            kept += len(chunk)


def _run_collect(proc: subprocess.Popen, timeout_s: float, on_timeout) -> tuple[str, str, bool]:
    """Collect capped stdout/stderr; on wall-clock timeout call ``on_timeout`` then reap."""
    out: list[bytes] = []
    err: list[bytes] = []
    threads = [
        threading.Thread(target=_drain, args=(proc.stdout, out), daemon=True),
        threading.Thread(target=_drain, args=(proc.stderr, err), daemon=True),
    ]
    for t in threads:
        t.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        on_timeout()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            proc.kill()
            proc.wait()
    for t in threads:
        t.join(timeout=5)
    dec = lambda b: b"".join(b).decode("utf-8", "replace")  # noqa: E731
    return dec(out), dec(err), timed_out


def _classify(code: int | None, stderr: str, timed_out: bool) -> tuple[bool, str | None]:
    """Return (killed_by_limit, reason)."""
    if timed_out:
        return False, "wall-clock timeout"
    sig = None
    if code is not None:
        if code < 0:
            sig = -code
        elif code >= 128:
            sig = code - 128
    if sig == 24:
        return True, "CPU time limit exceeded (SIGXCPU)"
    if sig == 25:
        return True, "file size limit exceeded (SIGXFSZ)"
    if "MemoryError" in stderr:
        return True, "memory limit exceeded (MemoryError)"
    if sig == 9:
        return True, "killed (SIGKILL: memory, CPU or pids limit)"
    if "Resource temporarily unavailable" in stderr or "BlockingIOError" in stderr:
        return True, "process limit exceeded (fork failed)"
    return False, None


def _base_python() -> str:
    return os.path.realpath(sys.executable)


def _resolve_argv(argv: list[str]) -> list[str]:
    """Map a bare ``python``/``python3`` to the interpreter we expose in the sandbox."""
    if argv and argv[0] in _PY_NAMES:
        return [_base_python(), *argv[1:]]
    return list(argv)


def _default_env(workdir: Path, extra: dict[str, str] | None) -> dict[str, str]:
    env = {
        "PATH": _SANDBOX_PATH,
        "HOME": str(workdir),
        "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
    }
    env.update(extra or {})
    return env


# --------------------------------------------------------------------------- unshare

# Runs INSIDE the new user+mount+pid(+net) namespaces as namespace-root. Reports setup
# status over a close-on-exec pipe so a PoC can never spoof a setup failure/success.
_STUB = r"""
import ctypes, json, os, resource, shutil, stat, sys

cfg = json.loads(sys.argv[1])
status = cfg["status_fd"]
os.set_inheritable(status, False)  # closed automatically at exec

def fail(msg):
    try:
        os.write(status, ("ERR:" + msg).encode())
    finally:
        os._exit(125)

libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p] * 3 + [ctypes.c_ulong, ctypes.c_char_p]
libc.syscall.restype = ctypes.c_long
MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC = 1, 2, 4, 8
MS_REMOUNT, MS_BIND, MS_REC, MS_PRIVATE = 32, 4096, 16384, 1 << 18
MNT_DETACH = 2
CLONE_NEWUSER = 0x10000000

def enc(p):
    return None if p is None else os.fsencode(p)

def mount(src, dst, fstype, flags, data=None):
    if libc.mount(enc(src), enc(dst), enc(fstype), flags, enc(data)) != 0:
        e = ctypes.get_errno()
        fail("mount %s -> %s failed: %s" % (src, dst, os.strerror(e)))

def locked_flags(path):
    f = os.statvfs(path).f_flag
    out = 0
    for st, ms in ((2, MS_NOSUID), (4, MS_NODEV), (8, MS_NOEXEC),
                   (1024, 1024), (2048, 2048), (4096, 1 << 21)):
        if f & st:
            out |= ms
    return out

NR = cfg["newroot"]

def target(path):
    return NR + os.path.normpath("/" + path)

def bind(src, ro):
    src = os.path.realpath(src)
    dst = target(src)
    if os.path.isdir(src):
        os.makedirs(dst, exist_ok=True)
    else:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if not os.path.exists(dst):
            open(dst, "a").close()
    mount(src, dst, None, MS_BIND)
    if ro:
        mount(None, dst, None, MS_BIND | MS_REMOUNT | MS_RDONLY | locked_flags(src))

try:
    mount(None, "/", None, MS_REC | MS_PRIVATE)
    mount("tmpfs", NR, "tmpfs", MS_NOSUID | MS_NODEV, "mode=755,size=4m")
    os.makedirs(NR + "/tmp", exist_ok=True)
    mount("tmpfs", NR + "/tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
          "mode=1777,size=%dm" % cfg["tmp_mb"])
    for d in cfg["sys_dirs"]:
        if os.path.islink(d):
            os.symlink(os.readlink(d), NR + d)
        elif os.path.isdir(d):
            bind(d, True)
    for p in cfg["ro_paths"]:
        bind(p, True)
    for p in cfg["dev_nodes"]:
        if os.path.exists(p):
            bind(p, False)
    bind(cfg["workdir"], False)
    os.makedirs(NR + "/proc", exist_ok=True)
    mount("proc", NR + "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC)
    # pivot into the new root, drop the old one
    os.makedirs(NR + "/.old", exist_ok=True)
    os.chdir(NR)
    nr = {"x86_64": 155, "aarch64": 41, "arm64": 41}.get(os.uname().machine)
    if nr is None:
        fail("pivot_root syscall number unknown for " + os.uname().machine)
    if libc.syscall(nr, b".", b".old") != 0:
        fail("pivot_root failed: %s" % os.strerror(ctypes.get_errno()))
    os.chdir("/")
    if libc.umount2(b"/.old", MNT_DETACH) != 0:
        fail("umount old root failed: %s" % os.strerror(ctypes.get_errno()))
    os.rmdir("/.old")
    # root fs becomes read-only (the writable bits are the workdir bind and /tmp only)
    mount(None, "/", None, MS_REMOUNT | MS_RDONLY | MS_BIND)
    # enter a nested user namespace as an unprivileged uid: no caps over our mounts
    uid, gid = cfg["uid"], cfg["gid"]
    if libc.unshare(CLONE_NEWUSER) != 0:
        fail("nested userns failed: %s" % os.strerror(ctypes.get_errno()))
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny")
    with open("/proc/self/uid_map", "w") as f:
        f.write("%d 0 1" % uid)
    with open("/proc/self/gid_map", "w") as f:
        f.write("%d 0 1" % gid)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        fail("no_new_privs failed")
    env = cfg["env"]
    argv = cfg["argv"]
    exe = argv[0] if os.sep in argv[0] else shutil.which(argv[0], path=env.get("PATH", ""))
    if not exe or not os.path.exists(exe):
        fail("executable not found in sandbox: %s" % argv[0])
except SystemExit:
    raise
except BaseException as e:  # any setup problem => never run the command
    fail("%s: %s" % (type(e).__name__, e))

child = os.fork()
if child == 0:
    try:
        mb = 1024 * 1024
        for res, val in (
            (resource.RLIMIT_AS, cfg["mem_mb"] * mb),
            (resource.RLIMIT_NPROC, cfg["pids"]),
            (resource.RLIMIT_NOFILE, 256),
            (resource.RLIMIT_FSIZE, cfg["fsize_mb"] * mb),
            (resource.RLIMIT_CORE, 0),
        ):
            resource.setrlimit(res, (val, val))
        resource.setrlimit(resource.RLIMIT_CPU, (cfg["cpu_s"], cfg["cpu_s"] + 1))
        os.chdir(cfg["workdir"])
        os.write(status, b"READY")
    except BaseException as e:
        fail("%s: %s" % (type(e).__name__, e))
    os.execve(exe, argv, env)

# pid 1 of the pid namespace: supervise, reap, enforce the process-count limit in
# user space (RLIMIT_NPROC is not enforced by the kernel for host-root callers).
import signal, time
def kill_all():
    for n in os.listdir("/proc"):
        if n.isdigit() and int(n) != 1:
            try:
                os.kill(int(n), signal.SIGKILL)
            except OSError:
                pass
verdict = None
code = 255
while True:
    try:
        pid, st = os.waitpid(-1, os.WNOHANG)
    except ChildProcessError:
        break
    if pid == child:
        code = os.WEXITSTATUS(st) if os.WIFEXITED(st) else 128 + os.WTERMSIG(st)
        kill_all()
        break
    if pid == 0:
        if sum(1 for n in os.listdir("/proc") if n.isdigit()) > cfg["pids"] + 1:
            verdict = "P"
            kill_all()
        time.sleep(0.02)
os.write(status, ("|%s%d" % (verdict or "X", code)).encode())
os._exit(0)
"""


def _sys_dirs() -> list[str]:
    dirs = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
    prefix = os.path.realpath(sys.base_prefix)
    if not any(prefix == d or prefix.startswith(d + "/") for d in dirs):
        dirs.append(prefix)
    return dirs


def _unshare_cmd(cfg: dict, network: bool) -> list[str]:
    cmd = ["unshare", "--user", "--map-root-user", "--mount", "--pid", "--kill-child"]
    if not network:
        cmd.append("--net")
    return [*cmd, "--", _base_python(), "-I", "-c", _STUB, json.dumps(cfg)]


def _run_unshare(
    argv, workdir, ro_paths, timeout_s, mem_mb, cpu_s, pids, network, env
) -> SandboxResult:
    newroot = tempfile.mkdtemp(prefix="vh-root-")
    r_fd, w_fd = os.pipe()
    try:
        st = os.stat(workdir)
        cfg = {
            "status_fd": w_fd,
            "newroot": newroot,
            "workdir": str(workdir),
            "ro_paths": [str(p) for p in ro_paths],
            "sys_dirs": _sys_dirs(),
            "dev_nodes": ["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"],
            "uid": 65534 if st.st_uid == 0 else st.st_uid,
            "gid": 65534 if st.st_gid == 0 else st.st_gid,
            "mem_mb": mem_mb,
            "cpu_s": cpu_s,
            "pids": pids,
            "fsize_mb": 64,
            "tmp_mb": 16,
            "env": _default_env(workdir, env),
            "argv": _resolve_argv(argv),
        }
        start = time.monotonic()
        proc = subprocess.Popen(
            _unshare_cmd(cfg, network),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            pass_fds=[w_fd],
            start_new_session=True,
        )
        os.close(w_fd)
        w_fd = -1

        def kill():
            try:
                os.killpg(proc.pid, 9)
            except OSError:
                proc.kill()

        out, err, timed_out = _run_collect(proc, timeout_s, kill)
        duration = time.monotonic() - start
        status = os.read(r_fd, 4096).decode("utf-8", "replace")
    finally:
        os.close(r_fd)
        if w_fd >= 0:
            os.close(w_fd)
        shutil.rmtree(newroot, ignore_errors=True)
    if not status.startswith("READY"):
        why = status[4:] if status.startswith("ERR:") else (err.strip()[-300:] or "setup aborted")
        return _unavailable(f"unshare sandbox setup failed: {why}", "unshare")
    tail = status.split("|", 1)[1] if "|" in status else "X137"  # no verdict: killed from outside
    code = int(tail[1:])  # supervisor-reported (128+sig if signalled)
    killed, reason = _classify(code, err, timed_out)
    if tail.startswith("P"):
        killed, reason = True, f"process limit exceeded (> {pids} processes)"
    if timed_out:
        reason = f"wall-clock timeout after {timeout_s:g}s"
    return SandboxResult("unshare", True, code, out, err, timed_out, killed, reason, duration)


_PROBE = (
    "import socket\n"
    "try:\n"
    "    open('/vh_probe','w'); print('FS-WRITABLE'); raise SystemExit\n"
    "except OSError: pass\n"
    "try:\n"
    "    socket.create_connection(('1.1.1.1',53),timeout=1); print('NET-UP'); raise SystemExit\n"
    "except OSError: pass\n"
    "print('CONFINED')\n"
)


@functools.lru_cache(maxsize=1)
def _unshare_ok() -> tuple[bool, str]:
    """Self-test the whole path once: setup works AND the result really is confined."""
    if not sys.platform.startswith("linux"):
        return False, "unshare backend is Linux-only"
    if shutil.which("unshare") is None:
        return False, "unshare binary not found"
    with tempfile.TemporaryDirectory(prefix="vh-probe-") as tmp:
        wd = Path(tmp) / "w"
        wd.mkdir()
        try:
            res = _run_unshare(["python3", "-c", _PROBE], wd, [], 15.0, 256, 10, 64, False, None)
        except Exception as e:  # noqa: BLE001
            return False, f"unshare probe error: {e}"
    if not res.available:
        return False, res.reason or "unshare setup failed"
    if res.stdout.strip() != "CONFINED":
        return False, f"unshare self-test not confined: {res.stdout.strip()!r} {res.stderr[-200:]}"
    return True, ""


# --------------------------------------------------------------------------- docker


def _docker_image() -> str:
    return os.environ.get(DOCKER_IMAGE_ENV, DEFAULT_IMAGE)


def _docker(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )


@functools.lru_cache(maxsize=4)
def _docker_ok(image: str) -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "docker binary not found"
    try:
        if _docker(["info", "--format", "{{.ServerVersion}}"], 8).returncode != 0:
            return False, "docker daemon not reachable"
        if _docker(["image", "inspect", image], 8).returncode == 0:
            return True, ""
        pull = _docker(["pull", "--quiet", image], 45)  # tried once per process
        if pull.returncode == 0:
            return True, ""
        return False, f"docker image {image} not available locally and pull failed"
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"docker unusable: {e}"


def _docker_cmd(
    name, image, argv, workdir, ro_paths, mem_mb, cpu_s, pids, network, env
) -> list[str]:
    st = os.stat(workdir)
    uid, gid = st.st_uid, st.st_gid  # owner of the scratch dir so it is writable
    wd = str(workdir)
    cmd = [
        "docker", "run", "--name", name,
        "--memory", f"{mem_mb}m", "--memory-swap", f"{mem_mb}m",
        "--pids-limit", str(pids),
        "--cpus", "1",
        "--ulimit", f"cpu={cpu_s}:{cpu_s + 1}",
        "--ulimit", "nofile=256:256",
        "--ulimit", "fsize=67108864:67108864",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "-u", f"{uid}:{gid}",
        "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL",
    ]  # fmt: skip
    if not network:
        cmd += ["--network=none"]
    for p in ro_paths:
        if str(p) != wd:
            cmd += ["-v", f"{p}:{p}:ro"]
    cmd += ["-v", f"{wd}:{wd}", "-w", wd]
    for k, v in _default_env(workdir, env).items():
        if k != "PATH":
            cmd += ["-e", f"{k}={v}"]
    return [*cmd, image, *argv]


def _run_docker(
    argv, workdir, ro_paths, timeout_s, mem_mb, cpu_s, pids, network, env
) -> SandboxResult:
    image = _docker_image()
    name = f"vulnhound-{uuid.uuid4().hex[:12]}"
    cmd = _docker_cmd(name, image, argv, workdir, ro_paths, mem_mb, cpu_s, pids, network, env)
    start = time.monotonic()
    proc = subprocess.Popen(
        cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    def kill():
        subprocess.run(["docker", "kill", name], capture_output=True, timeout=15)
        proc.kill()

    out, err, timed_out = _run_collect(proc, timeout_s, kill)
    duration = time.monotonic() - start
    oom = False
    try:
        ins = _docker(["inspect", "--format", "{{.State.OOMKilled}}", name], 10)
        oom = ins.stdout.strip() == "true"
    except (subprocess.TimeoutExpired, OSError):
        pass
    finally:
        try:
            _docker(["rm", "-f", name], 15)
        except (subprocess.TimeoutExpired, OSError):
            pass
    code = proc.returncode
    if code in (125, 126) and not timed_out and "docker:" in err:
        return _unavailable(f"docker run failed: {err.strip()[-300:]}", "docker")
    killed, reason = _classify(code, err, timed_out)
    if oom:
        killed, reason = True, "memory limit exceeded (OOM killed)"
    if timed_out:
        reason = f"wall-clock timeout after {timeout_s:g}s"
    return SandboxResult("docker", True, code, out, err, timed_out, killed, reason, duration)


# --------------------------------------------------------------------------- public API


def available_backends() -> list[str]:
    """Backends usable right now, best first. Never includes ``"none"``."""
    found = []
    if _docker_ok(_docker_image())[0]:
        found.append("docker")
    if _unshare_ok()[0]:
        found.append("unshare")
    return found


def run_sandboxed(
    argv: list[str],
    *,
    workdir: Path,
    read_only_paths: list[Path],
    timeout_s: float = 10.0,
    mem_mb: int = 512,
    cpu_s: int = 10,
    pids: int = 128,
    network: bool = False,
    env: dict[str, str] | None = None,
    backend: str | None = None,
) -> SandboxResult:
    """Run ``argv`` in a real sandbox, or run nothing and report unavailable."""
    workdir = Path(workdir).resolve()
    ro = [Path(p).resolve() for p in read_only_paths]
    if not argv:
        return _unavailable("empty argv")
    if not workdir.is_dir():
        return _unavailable(f"workdir does not exist: {workdir}")
    candidates = available_backends() if backend is None else [backend]
    if not candidates:
        reasons = [
            f"docker: {_docker_ok(_docker_image())[1]}",
            f"unshare: {_unshare_ok()[1]}",
        ]
        return _unavailable("no sandbox backend available (" + "; ".join(reasons) + ")")
    last: SandboxResult | None = None
    for b in candidates:
        if b == "docker":
            ok, why = _docker_ok(_docker_image())
            runner = _run_docker
        elif b == "unshare":
            ok, why = _unshare_ok()
            runner = _run_unshare
        else:
            return _unavailable(f"unknown backend: {b!r}")
        if not ok:
            last = _unavailable(why, b)
            continue
        res = runner(argv, workdir, ro, timeout_s, mem_mb, cpu_s, pids, network, env)
        if res.available:
            return res
        last = res  # setup failed before the command ran: try the next backend
    return last or _unavailable("no sandbox backend available")
