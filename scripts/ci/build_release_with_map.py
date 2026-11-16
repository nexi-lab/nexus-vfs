"""Build one release executable and retain its linker map for size analysis."""

import argparse
from pathlib import Path
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', required=True)
    parser.add_argument('--bin', required=True)
    parser.add_argument('--artifact', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--features', default='')
    parser.add_argument('--target', default='')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    link_map = args.output.resolve() / (args.artifact + '.map')
    if sys.platform == 'win32':
        link_arg = '/MAP:' + str(link_map)
    elif sys.platform == 'darwin':
        link_arg = '-Wl,-map,' + str(link_map)
    else:
        link_arg = '-Wl,-Map=' + str(link_map)
    command = ['cargo', 'rustc', '--release', '-p', args.package, '--bin', args.bin]
    if args.features:
        command += ['--features', args.features]
    if args.target:
        command += ['--target', args.target]
    command += ['--', '-C', 'link-arg=' + link_arg]
    return subprocess.run(command, check=False).returncode


if __name__ == '__main__':
    raise SystemExit(main())
