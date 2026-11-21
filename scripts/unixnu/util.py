"""Small helpers shared by the build driver."""
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


class Error(Exception):
    """A user-facing failure; the command line prints it without a traceback."""


TOKEN = re.compile(r'(?i)\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,})\b')
BEARER = re.compile(r'(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]+')
SECRET_QUERY = re.compile(
    r'(?i)([?&](?:token|access_token|id_token|api_key|apikey|key|sig|signature|credential|'
    r'x-amz-signature|x-amz-credential|x-amz-security-token|googleaccessid|policy|expires|'
    r'user|password|secret)=)([^&\s"\']+)')
URL_PASSWORD = re.compile(r'(?i)([a-z][a-z0-9+.-]*://)([^/@\s:]+):([^/@\s]+)@')
URL_USER = re.compile(r'(?i)([a-z][a-z0-9+.-]*://)([^/@\s]+)@')
SEED_ARG = re.compile(r'(?i)(--unique-chip-id\s+)(\S+)')
SEED_ASSIGN = re.compile(r'(?i)(\b(?:UNIXNU_)?unique[_-]?chip[_-]?id\s*[:=]\s*["\']?)([^\s,;&"\']+)')
ASSIGNMENT = re.compile(r'(?i)(\b(?:token|password|passwd|secret|api[_-]?key|authorization)\s*[:=]\s*)([^\s,;&"\']+)')


def redact(text):
    """Mask token-like, signed-URL and platform-seed values before a command or log is printed."""
    text = TOKEN.sub('<redacted>', text)
    text = BEARER.sub(r'\1<redacted>', text)
    text = SECRET_QUERY.sub(r'\1<redacted>', text)
    text = URL_PASSWORD.sub(r'\1<redacted>@', text)
    text = URL_USER.sub(r'\1<redacted>@', text)
    text = SEED_ARG.sub(r'\1<redacted>', text)
    text = SEED_ASSIGN.sub(r'\1<redacted>', text)
    return ASSIGNMENT.sub(r'\1<redacted>', text)


def log(message):
    print(f'== {message}', flush=True)


def expand(path):
    return Path(os.path.expandvars(os.path.expanduser(str(path)))).resolve()


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


EXTRA_BIN = ('/opt/homebrew/opt/llvm/bin', '/opt/homebrew/opt/lld/bin', '/usr/local/opt/llvm/bin', '/usr/local/opt/lld/bin')


def tool(name, hint=''):
    """Find a tool on PATH, then in the usual Homebrew LLVM locations (keg-only, not on PATH)."""
    found = shutil.which(name) or shutil.which(name, path=os.pathsep.join(EXTRA_BIN))
    if not found:
        raise Error(f'{name} not found on PATH' + (f' ({hint})' if hint else ''))
    return found


def lzfse():
    """Apple's reference LZFSE tool, which decodes LZFSE on Linux: in the scripts/linux/setup-toolchain.py prefix, else on PATH."""
    path = Path(os.environ.get('UNIXNU_TOOLCHAIN', '/opt/unixnu-linux')) / 'bin/lzfse'
    return str(path) if path.is_file() else tool('lzfse', 'run sudo scripts/linux/setup-toolchain.py')


def run(command, *, cwd=None, env=None, log_file=None, capture=False):
    """Run a command, echoing it. With log_file the output goes there and the tail is shown on failure."""
    command = [str(part) for part in command]
    if not capture:
        print('+ ' + redact(' '.join(command)), flush=True)
    if capture:
        result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True)
        if result.returncode:
            detail = redact(result.stderr.strip() or result.stdout.strip())
            raise Error(f'{command[0]} failed ({result.returncode}): {detail}')
        return result.stdout
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        with Path(log_file).open('w') as stream:
            result = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
        if result.returncode:
            tail = [redact(line) for line in Path(log_file).read_text(errors='replace').splitlines()[-30:]]
            print('\n'.join(tail), file=sys.stderr)
            raise Error(f'{command[0]} failed ({result.returncode}); full log: {log_file}')
        return ''
    result = subprocess.run(command, cwd=cwd, env=env)
    if result.returncode:
        raise Error(f'{command[0]} failed ({result.returncode})')
    return ''


def git(repo, *args, capture=True):
    return run(['git', '-C', repo, *args], capture=capture)


CLANGPDB_TOOLS = ('clang', 'lld-link', 'llvm-lib', 'llvm-rc')


def validate_clang_bin(directory):
    """Validate EDK II tools and return its required slash-terminated prefix."""
    directory = expand(directory)
    for name in CLANGPDB_TOOLS:
        binary = directory / name
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise Error(f'CLANGPDB tool missing or not executable: {binary}')
    versions = []
    for name in ('clang', 'lld-link'):
        output = run([directory / name, '--version'], capture=True)
        match = re.search(r'\b(\d+\.\d+\.\d+)\b', output)
        versions.append(match.group(1) if match else '')
    if not versions[0] or versions[0] != versions[1]:
        raise Error(f'CLANGPDB requires matching LLVM and LLD releases (clang {versions[0]}, LLD {versions[1]}); '
                    'set CLANG_BIN to a directory containing matching clang, lld-link, llvm-lib and llvm-rc')
    return str(directory) + '/'


def clang_bin(directory):
    """Link EDK II's CLANGPDB tools using the LLVM installation's COFF compiler."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    llvm_compiler = Path(tool('llvm-lib', 'brew install llvm')).resolve().parent / 'clang'
    compiler = str(llvm_compiler) if llvm_compiler.is_file() else tool('clang', 'brew install llvm')
    linker = tool('lld-link', 'brew install lld')
    for name in CLANGPDB_TOOLS:
        link = directory / name
        target = compiler if name == 'clang' else linker if name == 'lld-link' else tool(name, 'brew install llvm lld')
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(target)
    return validate_clang_bin(directory)
