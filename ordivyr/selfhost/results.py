"""Bounded owner retrieval of a completed drawing step's workspace files.

Directory descriptors anchor each lookup. Model-created symlinks, special files
and changing files cannot turn a download into an arbitrary host-file read.
"""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
import stat

MAX_BYTES = 2 * 1024 * 1024
MAX_FILES = 100
MAX_ENTRIES = 1000
MAX_DEPTH = 8
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def identity(info):
    return hashlib.sha256(json.dumps([info.st_dev, info.st_ino, info.st_mode,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]).encode()).hexdigest()


def parts(path):
    if not isinstance(path, str) or not path or '\\' in path or '\x00' in path:
        raise ValueError('Invalid result file path')
    names = path.split('/')
    if len(names) > MAX_DEPTH + 1 or any(not n or n.startswith('.') for n in names):
        raise ValueError('Invalid result file path')
    return names


@contextmanager
def attempt(home, task):
    descriptors = []
    try:
        fd = os.open(home, DIR_FLAGS); descriptors.append(fd)
        for name in ('ws', str(task['id']), 'a' + str(task['fence'])):
            fd = os.open(name, DIR_FLAGS, dir_fd=fd); descriptors.append(fd)
        yield fd
    finally:
        for fd in reversed(descriptors): os.close(fd)


def list_files(home, task):
    files = []; examined = 0; truncated = False

    def walk(fd, prefix, depth):
        nonlocal examined, truncated
        with os.scandir(fd) as entries:
            for entry in entries:
                examined += 1
                if examined > MAX_ENTRIES or len(files) >= MAX_FILES:
                    truncated = True; return
                if entry.name.startswith('.') or '\\' in entry.name: continue
                name = prefix + entry.name
                try:
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        if depth >= MAX_DEPTH:
                            truncated = True; continue
                        child = os.open(entry.name, DIR_FLAGS, dir_fd=fd)
                        try: walk(child, name + '/', depth + 1)
                        finally: os.close(child)
                        if examined > MAX_ENTRIES or len(files) >= MAX_FILES:
                            truncated = True; return
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        files.append({'path': name, 'bytes': info.st_size, 'identity': identity(info),
                                      'downloadable': info.st_size <= MAX_BYTES})
                except OSError:
                    continue  # a disappeared/replaced entry is not a downloadable result
    try:
        with attempt(home, task) as fd: walk(fd, '', 0)
    except OSError:
        return {'files': [], 'truncated': False, 'available': False, 'max_download_bytes': MAX_BYTES}
    return {'files': sorted(files, key=lambda f: f['path']), 'truncated': truncated,
            'available': True, 'max_download_bytes': MAX_BYTES}


def read_file(home, task, path, expected):
    names = parts(path)
    if not isinstance(expected, str) or len(expected) != 64:
        raise ValueError('Refresh results before downloading this file')
    descriptors = []
    try:
        with attempt(home, task) as root:
            parent = root
            for name in names[:-1]:
                parent = os.open(name, DIR_FLAGS, dir_fd=parent); descriptors.append(parent)
            fd = os.open(names[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            descriptors.append(fd)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError('Result must be a regular workspace file')
            if before.st_size > MAX_BYTES: raise ValueError('Result exceeds the download size limit')
            if identity(before) != expected: raise ValueError('Result changed; refresh results before downloading')
            chunks = []; total = 0
            while True:
                chunk = os.read(fd, min(65536, MAX_BYTES + 1 - total))
                if not chunk: break
                chunks.append(chunk); total += len(chunk)
                if total > MAX_BYTES: raise ValueError('Result exceeds the download size limit')
            if identity(os.fstat(fd)) != expected:
                raise ValueError('Result changed during download; refresh results')
            data = b''.join(chunks)
            return {'path': path, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                    'base64': base64.b64encode(data).decode('ascii')}
    except OSError as exc:
        raise ValueError('Result is unavailable; refresh results') from exc
    finally:
        for fd in reversed(descriptors): os.close(fd)
