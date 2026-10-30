"""Read-only byte-offset cursor. Collector keeps durable and buffered cursors separate."""
from dataclasses import dataclass
from pathlib import Path
import os
import uuid
import stat as stat_module
import re


class SourceError(RuntimeError):
    def __init__(self, code='SOURCE_UNAVAILABLE'):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Checkpoint:
    generation: str
    device: int
    inode: int
    offset: int


@dataclass(frozen=True)
class Candidate:
    before: Checkpoint
    after: Checkpoint
    raw: bytes | None = None
    reason: str | None = None


def generation(device, inode):
    return f'{device}:{inode}:{uuid.uuid4()}'


def checkpoint_json(checkpoint):
    from .algorithms import canonical
    return canonical({'generation': checkpoint.generation, 'offset': str(checkpoint.offset)}).decode()


def restore_checkpoint(encoded):
    import json
    try:
        value = json.loads(encoded)
        if set(value) != {'generation', 'offset'} or not isinstance(value['generation'], str):
            raise ValueError()
        parts = value['generation'].split(':')
        if len(parts) != 3 or not all(part.isdecimal() for part in parts[:2]) or str(uuid.UUID(parts[2])) != parts[2]:
            raise ValueError()
        if not isinstance(value['offset'], str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', value['offset']):
            raise ValueError()
        return Checkpoint(value['generation'], int(parts[0]), int(parts[1]), int(value['offset']))
    except (KeyError, ValueError, TypeError):
        raise ValueError('INVALID_CHECKPOINT') from None


class FileTailer:
    def __init__(self, path, checkpoint=None, max_line_bytes=65536):
        if max_line_bytes < 1:
            raise ValueError('INVALID_LINE_LIMIT')
        self.path = Path(path)
        self.max_line_bytes = max_line_bytes
        self.handle = None
        self.checkpoint = checkpoint
        self.pending = None

    def close(self):
        if self.handle is not None:
            self.handle.close()
            self.handle = None

    def _open(self):
        paths = [self.path]
        if self.checkpoint is not None:
            # Match renamed files by inode; never read unrelated rotated sources.
            paths += sorted(self.path.parent.iterdir())
        for path in paths:
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
                handle = os.fdopen(descriptor, 'rb')
                stat = os.fstat(handle.fileno())
                if not stat_module.S_ISREG(stat.st_mode):
                    handle.close()
                    continue
                if self.checkpoint is not None and (stat.st_dev, stat.st_ino) != (self.checkpoint.device, self.checkpoint.inode):
                    handle.close()
                    continue
                self.handle = handle
                if self.checkpoint is None:
                    self.checkpoint = Checkpoint(generation(stat.st_dev, stat.st_ino), stat.st_dev, stat.st_ino, 0)
                return
            except (FileNotFoundError, IsADirectoryError, PermissionError):
                continue
        if self.checkpoint is not None:
            raise SourceError('CHECKPOINT_FILE_UNAVAILABLE')
        raise SourceError()

    def prepare(self):
        try:
            return self._prepare()
        except OSError:
            raise SourceError() from None

    def _prepare(self):
        if self.pending is not None:
            return self.pending
        if self.handle is None:
            self._open()
        if self.handle is None:
            raise SourceError()
        before = self.checkpoint
        stat = os.fstat(self.handle.fileno())
        if stat.st_size < before.offset:
            after = Checkpoint(generation(stat.st_dev, stat.st_ino), stat.st_dev, stat.st_ino, 0)
            self.pending = Candidate(before, after, reason='SOURCE_TRUNCATED')
            return self.pending
        self.handle.seek(before.offset)
        raw = self.handle.readline(self.max_line_bytes + 1)
        if raw.endswith(b'\n'):
            reason = 'LINE_TOO_LONG' if len(raw) > self.max_line_bytes else None
            self.pending = Candidate(before, Checkpoint(before.generation, before.device, before.inode, before.offset + len(raw)), None if reason else raw, reason)
            return self.pending
        if len(raw) > self.max_line_bytes:
            # Consume an oversized line in bounded memory, but wait for its LF.
            consumed = len(raw)
            while True:
                chunk = self.handle.readline(self.max_line_bytes + 1)
                consumed += len(chunk)
                if chunk.endswith(b'\n'):
                    self.pending = Candidate(before, Checkpoint(before.generation, before.device, before.inode, before.offset + consumed), reason='LINE_TOO_LONG')
                    return self.pending
                if not chunk:
                    break
        try:
            current = self.path.stat()
        except OSError:
            raise SourceError() from None
        if (current.st_dev, current.st_ino) != (before.device, before.inode):
            # Verify the new target is readable before acknowledging any switch.
            try:
                descriptor = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK)
                with os.fdopen(descriptor, 'rb') as target:
                    verified = os.fstat(target.fileno())
                    if not stat_module.S_ISREG(verified.st_mode) or (verified.st_dev, verified.st_ino) != (current.st_dev, current.st_ino):
                        raise SourceError()
            except OSError:
                raise SourceError() from None
            # Old inode drained. Partial final line is a safe fixed quality event.
            after = Checkpoint(generation(current.st_dev, current.st_ino), current.st_dev, current.st_ino, 0)
            self.pending = Candidate(before, after, reason='ROTATED_PARTIAL_LINE' if raw else 'SOURCE_ROTATED')
            return self.pending
        # Incomplete line: retain its starting offset and retry on append/restart.
        return None

    def acknowledge(self, candidate):
        if candidate is not self.pending or candidate.before != self.checkpoint:
            raise RuntimeError('STALE_CANDIDATE')
        if (candidate.after.device, candidate.after.inode) != (candidate.before.device, candidate.before.inode):
            self.close()
        self.checkpoint = candidate.after
        self.pending = None
