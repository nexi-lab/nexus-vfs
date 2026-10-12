import io
import os
import pathlib
import platform
import subprocess
import time
import urllib.error
import urllib.request
import zipfile

VERSION = '3.20.2'
system = platform.system()
machine = platform.machine().lower()
if system == 'Windows':
    target = 'win64'
    executable = 'protoc.exe'
else:
    architecture = {'arm64': 'aarch_64', 'aarch64': 'aarch_64', 'x86_64': 'x86_64'}[machine]
    target = {'Darwin': 'osx', 'Linux': 'linux'}[system] + '-' + architecture
    executable = 'protoc'
url = f'https://github.com/protocolbuffers/protobuf/releases/download/v{VERSION}/protoc-{VERSION}-{target}.zip'
for attempt in range(4):
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read(32 * 1024 * 1024 + 1)
        break
    except urllib.error.HTTPError as error:
        if attempt == 3 or error.code not in (429, 500, 502, 503, 504):
            raise
        time.sleep(2 ** attempt)
    except (urllib.error.URLError, TimeoutError):
        if attempt == 3:
            raise
        time.sleep(2 ** attempt)
if len(data) > 32 * 1024 * 1024:
    raise ValueError('protobuf compiler archive exceeds its size limit')
directory = pathlib.Path(os.environ['RUNNER_TEMP']) / 'nexus-protoc'
directory.mkdir(exist_ok=True)
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    for entry in archive.infolist():
        path = (directory / entry.filename).resolve()
        if not path.is_relative_to(directory.resolve()):
            raise ValueError('protobuf compiler archive contains an invalid path')
    archive.extractall(directory)
binary = directory / 'bin' / executable
binary.chmod(0o755)
version = subprocess.check_output([str(binary), '--version'], text=True).strip()
if version != f'libprotoc {VERSION}':
    raise ValueError('protobuf compiler version differs from the build contract')
with open(os.environ['GITHUB_PATH'], 'a', encoding='utf-8') as output:
    output.write(str(binary.parent) + '\n')
with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as output:
    output.write('PROTOC=' + str(binary) + '\n')
print(version)
