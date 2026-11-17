"""Download and safely extract vulnerable/fixed releases listed in cves.json.

Usage: fetch_cves.py [--cache DIR] [--entries cves.json]

Archives are only extracted (tarfile filter='data', zipfile with path checks); nothing
is ever installed, imported or executed. Layout: <cache>/<pkg>-<version>/<extracted tree>.
Existing directories (with a .done marker) are skipped.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CACHE = Path.home() / ".cache" / "vulnhound" / "cvecorpus"


def release_dir(cache: Path, pkg: str, version: str) -> Path:
    return cache / f"{pkg}-{version}"


def _safe_unzip(zf: zipfile.ZipFile, dest: Path) -> None:
    root = dest.resolve()
    for info in zf.infolist():
        target = (dest / info.filename).resolve()
        if root != target and root not in target.parents:
            raise RuntimeError(f"unsafe path in zip: {info.filename}")
        # Never materialize symlinks from zips (external_attr high bits = unix mode)
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            continue
        zf.extract(info, dest)


def extract(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    name = archive.name
    if name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar")):
        with tarfile.open(archive) as tf:
            tf.extractall(dest, filter="data")
    elif name.endswith((".zip", ".whl")):
        with zipfile.ZipFile(archive) as zf:
            _safe_unzip(zf, dest)
    else:
        raise RuntimeError(f"unknown archive type: {name}")


def _pip_download(pkg: str, version: str, out: Path, sdist: bool) -> bool:
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--no-deps",
        "-q",
        f"{pkg}=={version}",
        "-d",
        str(out),
    ]
    cmd += ["--no-binary", ":all:"] if sdist else ["--only-binary", ":all:"]
    # --no-binary :all: on an sdist makes pip run metadata prep (setup.py) in some versions;
    # avoid that by fetching the sdist URL ourselves from PyPI's JSON API instead.
    return False if sdist else subprocess.run(cmd, capture_output=True).returncode == 0


def _fetch_sdist(pkg: str, version: str, out: Path) -> bool:
    import urllib.request

    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/{version}/json", timeout=60) as r:
            urls = json.load(r)["urls"]
    except Exception:
        return False
    for u in urls:
        if u["packagetype"] == "sdist":
            with urllib.request.urlopen(u["url"], timeout=300) as r:
                (out / u["filename"]).write_bytes(r.read())
            return True
    return False


def fetch(cache: Path, pkg: str, version: str) -> Path:
    dest = release_dir(cache, pkg, version)
    if (dest / ".done").exists():
        return dest
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        # sdist preferred (what the advisory describes); wheel fallback. Download only, never build.
        if not _fetch_sdist(pkg, version, out) and not _pip_download(
            pkg, version, out, sdist=False
        ):
            raise RuntimeError(f"cannot download {pkg}=={version}")
        stage = out / "x"
        for a in list(out.iterdir()):
            extract(a, stage)
        # sdists wrap everything in <pkg>-<ver>/: flatten so paths are relative to the source root
        tops = [p for p in stage.iterdir()]
        src = tops[0] if len(tops) == 1 and tops[0].is_dir() else stage
        dest.mkdir(parents=True, exist_ok=True)
        for p in src.iterdir():
            p.rename(dest / p.name)
    (dest / ".done").write_text("ok\n")
    return dest


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    ap.add_argument("--entries", type=Path, default=HERE / "cves.json")
    args = ap.parse_args()
    entries = json.loads(args.entries.read_text())
    rc = 0
    for e in entries:
        for ver in (e["vulnerable"], e["fixed"]):
            try:
                d = fetch(args.cache, e["package"], ver)
                print(f"ok   {e['package']}-{ver} -> {d}")
            except Exception as ex:  # keep going; report at the end
                print(f"FAIL {e['package']}-{ver}: {ex}")
                rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
