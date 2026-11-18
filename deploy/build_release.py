"""Build an allowlisted deployment archive and a clean public source tree."""

import argparse
import gzip
import hashlib
from io import BytesIO
from pathlib import Path
import re
import shutil
import tarfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE_EXTRA = ("deploy/build_release.py", "deploy/release-files.txt", "tests/", "hy2-lite-api-audit.sh", ".gitignore")
TEXT_SUFFIXES = {".py", ".html", ".js", ".css", ".sh", ".service", ".timer", ".caddyfile"}
FORBIDDEN = re.compile(rb"collector-stage-[a-z0-9]+|[l]ocal-acceptance|[/]root/vps-backups/", re.I)


def gather(root, entries):
    result = {"README.md": root / "docs/PUBLIC_README.md"}
    for entry in entries:
        path = root / entry
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError(f"Invalid release path: {entry}")
        if path.is_dir():
            for child in path.rglob("*"):
                relative = child.relative_to(root)
                if "__pycache__" in relative.parts:
                    continue
                if (child.is_file() and (child.suffix.lower() in TEXT_SUFFIXES or
                                        child.name == "publish-certificate")):
                    if child.is_symlink() or not child.resolve().is_relative_to(root):
                        raise ValueError(f"Invalid release file: {relative}")
                    result[relative.as_posix()] = child
        elif path.is_file():
            result[path.relative_to(root).as_posix()] = path
        else:
            raise ValueError(f"Missing release file: {entry}")
    for name, path in result.items():
        if FORBIDDEN.search(path.read_bytes()):
            raise ValueError(f"Private deployment reference in: {name}")
    return result


def build(version, destination):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc(?:\.[0-9]+)?)?", version):
        raise ValueError("Expected a version such as 0.1.0-rc")
    entries = [line for raw in (ROOT / "deploy/release-files.txt").read_text(encoding="utf-8").splitlines()
               if (line := raw.strip()) and not line.startswith("#")]
    deployment = gather(ROOT, entries)
    source = gather(ROOT, [*entries, *SOURCE_EXTRA, "docs/PUBLIC_README.md"])
    if (ROOT / "LICENSE").is_file():
        deployment.update(gather(ROOT, ["LICENSE"]))
        source.update(gather(ROOT, ["LICENSE"]))
    elif "-rc" not in version:
        raise ValueError("Select an open-source license before building a final release")
    prefix = f"hy2-lite-v{version}"
    destination.mkdir(parents=True, exist_ok=False)
    archive = destination / f"{prefix}-linux-amd64.tar.gz"
    payloads = {name: file.read_bytes() for name, file in deployment.items()}
    payloads["SHA256SUMS"] = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n"
                                    for name, data in sorted(payloads.items())).encode("ascii")
    with archive.open("xb") as stream, gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as bundle:
            for name, data in sorted(payloads.items()):
                info = tarfile.TarInfo(f"{prefix}/{name}")
                info.mode = 0o644
                info.size = len(data)
                bundle.addfile(info, BytesIO(data))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    for name, path in sorted(source.items()):
        target = destination / "public-source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    print(f"{digest}  {archive.name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    build(args.version, args.destination)
