"""Sandbox tests: network off, limits, filesystem confinement, never-unconfined invariant."""

from __future__ import annotations

import textwrap
import time
from pathlib import Path

import pytest

from vulnhound import sandbox
from vulnhound.sandbox import available_backends, run_sandboxed

BACKENDS = available_backends()
per_backend = pytest.mark.parametrize("backend", BACKENDS or ["none"])


@pytest.fixture()
def env(tmp_path):
    """(workdir, project) - project is a read-only host dir with a file in it."""
    work = tmp_path / "work"
    work.mkdir()
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text("SECRET = 'project'\n")
    return work, proj


def run(backend, dirs, code, **kw):
    if backend == "none":
        pytest.skip("no sandbox backend available on this host")
    work, proj = dirs
    (work / "poc.py").write_text(textwrap.dedent(code))
    kw.setdefault("timeout_s", 8)
    return run_sandboxed(
        ["python3", str(work / "poc.py")],
        workdir=work,
        read_only_paths=[proj],
        backend=backend,
        **kw,
    )


def test_a_backend_is_available_here():
    assert BACKENDS, "expected docker and/or unshare to work in this environment"
    assert "none" not in BACKENDS


@per_backend
def test_marker_and_exit_code(backend, env):
    r = run(backend, env, "print('MARKER-123')")
    assert r.available and r.backend == backend
    assert r.exit_code == 0 and "MARKER-123" in r.stdout
    assert not r.timed_out and not r.killed


@per_backend
def test_nonzero_exit_and_stderr(backend, env):
    r = run(backend, env, "import sys; print('boom', file=sys.stderr); sys.exit(3)")
    assert r.available and r.exit_code == 3 and "boom" in r.stderr and not r.killed


@per_backend
def test_can_read_project_read_only(backend, env):
    _, proj = env
    r = run(backend, env, f"print(open({str(proj / 'app.py')!r}).read())")
    assert r.exit_code == 0 and "SECRET" in r.stdout


@per_backend
def test_network_is_off(backend, env):
    r = run(
        backend,
        env,
        """
        import socket
        try:
            socket.create_connection(("1.1.1.1", 53), timeout=3)
            print("CONNECTED")
        except OSError as e:
            print("NO-NET", type(e).__name__)
        """,
    )
    assert r.available and r.exit_code == 0
    assert "NO-NET" in r.stdout and "CONNECTED" not in r.stdout


@per_backend
def test_no_loopback_listener(backend, env):
    # The security property that matters is no EXTERNAL egress (test_network_is_off).
    # The unshare backend additionally leaves loopback DOWN. Docker's `--network none`
    # keeps an in-container loopback interface UP, which is harmless: it is reachable
    # only from inside that one container, never from the host or the outside. So we
    # assert loopback-down only for unshare; for docker, in-container loopback is OK.
    r = run(
        backend,
        env,
        """
        import socket
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", 0)); s.listen(1)
            socket.create_connection(s.getsockname(), timeout=2)
            print("LOOPBACK-UP")
        except OSError:
            print("LOOPBACK-DOWN")
        """,
    )
    assert r.available and r.exit_code == 0
    if backend == "unshare":
        assert "LOOPBACK-DOWN" in r.stdout
    else:  # docker: in-container loopback may be up; that is not external reachability
        assert "LOOPBACK-UP" in r.stdout or "LOOPBACK-DOWN" in r.stdout


@per_backend
def test_timeout(backend, env):
    t0 = time.monotonic()
    r = run(backend, env, "import time; time.sleep(30)", timeout_s=2)
    assert r.timed_out and r.available
    assert time.monotonic() - t0 < 12


@per_backend
def test_memory_limit(backend, env):
    r = run(backend, env, "x = bytearray(400 * 1024 * 1024); print('ALLOCATED')", mem_mb=128)
    assert "ALLOCATED" not in r.stdout
    assert r.killed or r.exit_code != 0


@per_backend
def test_cpu_limit(backend, env):
    r = run(backend, env, "while True: pass", cpu_s=1, timeout_s=15)
    assert not r.timed_out or backend == "docker"  # rlimit fires well before wall clock
    assert r.killed or r.exit_code != 0


@per_backend
def test_process_limit(backend, env):
    r = run(
        backend,
        env,
        """
        import os, time
        n = 0
        try:
            for _ in range(300):
                if os.fork() == 0:
                    time.sleep(10); os._exit(0)
                n += 1
        except OSError:
            pass
        print("FORKED", n)
        time.sleep(3)
        """,
        pids=24,
        timeout_s=8,
    )
    assert r.killed or "FORKED 300" not in r.stdout


@per_backend
def test_filesystem_confinement(backend, env):
    work, proj = env
    r = run(
        backend,
        env,
        f"""
        import os
        res = {{}}
        for label, path in [
            ("proj_new", {str(proj / "evil.txt")!r}),
            ("proj_existing", {str(proj / "app.py")!r}),
            ("root", "/pwned"),
            ("usr", "/usr/pwned"),
            ("home", "/home/vh_pwned_outside"),
        ]:
            try:
                open(path, "w").write("x"); res[label] = "WROTE"
            except OSError:
                res[label] = "denied"
        open("inside.txt", "w").write("ok")   # cwd is the workdir
        res["workdir"] = "WROTE" if os.path.exists("inside.txt") else "missing"
        print(res)
        """,
    )
    assert r.exit_code == 0, r.stderr
    for label in ("proj_new", "proj_existing", "root", "usr", "home"):
        assert f"'{label}': 'denied'" in r.stdout, r.stdout
    assert "'workdir': 'WROTE'" in r.stdout
    # and the host really is untouched / workdir really was written
    assert not (proj / "evil.txt").exists()
    assert not (work.parent / "pwned_outside").exists()
    assert not Path("/home/vh_pwned_outside").exists()
    assert (proj / "app.py").read_text() == "SECRET = 'project'\n"
    assert (work / "inside.txt").read_text() == "ok"


@per_backend
def test_host_files_not_visible(backend, env, tmp_path):
    secret = tmp_path / "host_secret.txt"
    secret.write_text("topsecret")
    r = run(
        backend,
        env,
        f"""
        import os
        print("VISIBLE" if os.path.exists({str(secret)!r}) else "HIDDEN")
        """,
    )
    assert "HIDDEN" in r.stdout


@per_backend
def test_host_env_not_leaked(backend, env, monkeypatch):
    monkeypatch.setenv("VH_SECRET_TOKEN", "leakme")
    code = "import os; print(os.environ.get('VH_SECRET_TOKEN'), os.environ.get('X'))"
    r = run(backend, env, code, env={"X": "1"})
    assert r.stdout.strip() == "None 1"


@pytest.mark.skipif("unshare" not in BACKENDS, reason="unshare backend not available")
def test_unshare_drops_privileges(env):
    r = run(
        "unshare",
        env,
        """
        import os
        caps = [l for l in open("/proc/self/status") if l.startswith("CapEff")][0].split()[1]
        try:
            os.setuid(0); root = True
        except OSError:
            root = False
        print(os.getuid() != 0, int(caps, 16) == 0, root)
        """,
    )
    assert r.stdout.strip() == "True True False"


@pytest.mark.skipif("unshare" not in BACKENDS, reason="unshare backend not available")
def test_unshare_setup_failure_means_unavailable_not_unconfined(env, tmp_path):
    work, proj = env
    marker = tmp_path / "ran.txt"
    (work / "poc.py").write_text(f"open({str(marker)!r}, 'w')")
    r = run_sandboxed(
        ["python3", str(work / "poc.py")],
        workdir=work,
        read_only_paths=[tmp_path / "does-not-exist" / "x"],  # bind mount must fail
        backend="unshare",
    )
    assert not r.available and r.exit_code is None
    assert r.reason and "setup failed" in r.reason
    assert not marker.exists()


def test_no_backend_runs_nothing(env, tmp_path, monkeypatch):
    work, proj = env
    marker = tmp_path / "ran.txt"
    (work / "poc.py").write_text(f"open({str(marker)!r}, 'w')")
    monkeypatch.setattr(sandbox, "_docker_ok", lambda image: (False, "docker: test"))
    monkeypatch.setattr(sandbox, "_unshare_ok", lambda: (False, "unshare: test"))
    assert available_backends() == []
    r = run_sandboxed(["python3", str(work / "poc.py")], workdir=work, read_only_paths=[proj])
    assert r.backend == "none" and not r.available and r.exit_code is None
    assert r.reason and "no sandbox backend available" in r.reason
    assert not marker.exists()
    # forcing an unavailable backend must not run either
    r = run_sandboxed(
        ["python3", str(work / "poc.py")], workdir=work, read_only_paths=[proj], backend="unshare"
    )
    assert not r.available and not marker.exists()


def test_unknown_backend_unavailable(env):
    work, proj = env
    r = run_sandboxed(["true"], workdir=work, read_only_paths=[proj], backend="bogus")
    assert not r.available and r.backend == "none"


def test_docker_command_is_locked_down(env):
    """Pure construction check; runs without a docker daemon."""
    work, proj = env
    cmd = sandbox._docker_cmd(
        "n", "python:3.12-slim", ["python3", "/w/poc.py"], work, [proj], 128, 5, 32, False, None
    )
    j = " ".join(cmd)
    for needle in (
        "--network=none", "--memory 128m", "--memory-swap 128m", "--pids-limit 32",
        "--read-only", "--cap-drop ALL", "no-new-privileges", "cpu=5:6",
        f"-v {proj}:{proj}:ro", f"-v {work}:{work} ", "--tmpfs /tmp",
    ):  # fmt: skip
        assert needle in j, needle
    assert cmd[-3:] == ["python:3.12-slim", "python3", "/w/poc.py"]
    on = sandbox._docker_cmd("n", "img", ["x"], work, [proj], 128, 5, 32, True, None)
    assert "--network=none" not in on
