from pathlib import Path
import os
import platform
import sys


def main() -> int:
    workspace = Path(".microbox-demo")
    workspace.mkdir(exist_ok=True)

    report = workspace / "hello.txt"
    report.write_text(
        "\n".join(
            [
                "MicroBox demo",
                f"python = {sys.version.split()[0]}",
                f"platform = {platform.system().lower()}",
                f"cwd = {Path.cwd()}",
                f"hello = {os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    print("MicroBox demo completed")
    print(f"wrote = {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
