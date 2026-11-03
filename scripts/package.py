#!/usr/bin/env python3
"""Create a source distribution for a Linux VM. No samples or secrets included."""

import hashlib
from pathlib import Path
import tarfile


def main():
    root = Path(__file__).resolve().parents[1]
    files = [root / name for name in ("README.md", "requirements.txt", "upstream-manifest.json")]
    for directory in ("scripts", "probes", "recipes", "tests", "diagnostics"):
        files.extend(path for path in (root / directory).rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts and path.suffix in (".py", ".yaml", ".md", ".png"))
    output = root / "dist" / "mal-sim-linux-source.tar.gz"
    output.parent.mkdir(exist_ok=True)
    with tarfile.open(output, "w:gz") as archive:
        for path in sorted(files):
            archive.add(path, arcname="mal-sim/" + path.relative_to(root).as_posix(), recursive=False)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + ".sha256").write_text(f"{digest}  {output.name}\n", encoding="ascii")
    print(output)
    print("SHA256 " + digest)


if __name__ == "__main__":
    main()
