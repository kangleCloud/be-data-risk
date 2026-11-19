"""Fixed-host password SSH; credentials never enter command arguments or diagnostics."""
from dataclasses import dataclass, field
from pathlib import Path
import ipaddress
import os
import re
import selectors
import signal
import subprocess
import time

from .resources import REMOTE_PROBE_COMMAND

SSH_FAILURES = frozenset({
    'SSH_BINDING_UNAVAILABLE', 'SSH_CONNECTION_FAILED',
})
HOST_RE = re.compile(r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')


def _valid_host(value):
    if not isinstance(value, str) or not value or value.startswith('-') or any(ord(char) < 33 or ord(char) > 126 for char in value):
        return False
    try:
        address = ipaddress.ip_address(value)
        return not (address.is_multicast or address.is_unspecified)
    except ValueError:
        return bool(HOST_RE.fullmatch(value))


class SshBindingError(RuntimeError):
    def __init__(self, code='SSH_BINDING_UNAVAILABLE'):
        self.code = code if code in SSH_FAILURES else 'SSH_BINDING_UNAVAILABLE'
        super().__init__(self.code)


@dataclass(frozen=True)
class SSHBinding:
    host: str
    port: int
    username: str
    password: str = field(repr=False)


@dataclass(frozen=True)
class SshResult:
    ok: bool
    output: str = ''
    failure_code: str | None = None


def _binding(value):
    if not isinstance(value, dict) or set(value) != {'host', 'port', 'username', 'password'}:
        raise SshBindingError()
    host, port, username, password = (value[key] for key in ('host', 'port', 'username', 'password'))
    if not _valid_host(host) or type(port) is not int or not 1 <= port <= 65535:
        raise SshBindingError()
    if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', username):
        raise SshBindingError()
    if not isinstance(password, str) or not password or any(c in password for c in ('\n', '\r', '\x00')):
        raise SshBindingError()
    try:
        if len(password.encode('utf-8')) > 1024:
            raise SshBindingError()
    except UnicodeError:
        raise SshBindingError() from None
    return SSHBinding(host, port, username, password)


class SshAllowlist:
    """The private local list must match the Java target host, port and account."""
    def __init__(self, bindings=()):
        self.bindings = tuple(bindings)
        keys = [(item.host, item.port, item.username) for item in self.bindings]
        if len(set(keys)) != len(keys):
            raise SshBindingError()

    @classmethod
    def from_config(cls, values):
        if not isinstance(values, list) or len(values) > 1000:
            raise SshBindingError()
        return cls(_binding(item) for item in values)

    def resolve(self, connection):
        for binding in self.bindings:
            if (binding.host, binding.port, binding.username) == (connection.host, connection.port, connection.username):
                return binding
        raise SshBindingError('SSH_BINDING_UNAVAILABLE')


class SshRunner:
    """Runs only constant commands through a fixed, verified destination."""

    def __init__(self, max_output=524288, popen=None):
        self.max_output = max_output
        self.popen = popen or subprocess.Popen

    def __call__(self, binding, command, timeout):
        if command != REMOTE_PROBE_COMMAND:
            raise SshBindingError('SSH_CONNECTION_FAILED')
        if timeout <= 0:
            return SshResult(False, failure_code='SSH_COMMAND_TIMEOUT')
        connect = max(1, min(30, int(timeout) or 1))
        read_fd, write_fd = os.pipe()
        args = [
            'sshpass', '-d', str(read_fd), 'ssh', '-F', '/dev/null',
            '-o', 'BatchMode=no',
            '-o', 'PreferredAuthentications=password',
            '-o', 'NumberOfPasswordPrompts=1',
            '-o', 'RequestTTY=no',
            '-o', 'ClearAllForwardings=yes',
            '-o', 'PermitLocalCommand=no',
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + str(Path.home() / '.ssh' / 'known_hosts'),
            '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'ConnectTimeout=' + str(connect),
            '-o', 'ServerAliveInterval=5',
            '-o', 'ServerAliveCountMax=1',
            '-o', 'LogLevel=ERROR',
            '-p', str(binding.port),
            binding.username + '@' + binding.host,
            command,
        ]
        try:
            os.write(write_fd, binding.password.encode('utf-8') + b'\n')
            process = self.popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, close_fds=True, pass_fds=(read_fd,), start_new_session=True)
        except (OSError, ValueError):
            return SshResult(False, failure_code='SSH_CONNECTION_FAILED')
        finally:
            os.close(read_fd)
            os.close(write_fd)
        deadline = time.monotonic() + timeout
        output = bytearray()
        selector = selectors.DefaultSelector()
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._kill(process)
                    return SshResult(False, failure_code='SSH_COMMAND_TIMEOUT')
                if not selector.select(min(remaining, 0.2)):
                    if process.poll() is not None:
                        break
                    continue
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > self.max_output:
                    self._kill(process)
                    return SshResult(False, failure_code='SSH_OUTPUT_TOO_LARGE')
            remaining = max(0, deadline - time.monotonic())
            try:
                code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                self._kill(process)
                return SshResult(False, failure_code='SSH_COMMAND_TIMEOUT')
            if time.monotonic() > deadline:
                self._kill(process)
                return SshResult(False, failure_code='SSH_COMMAND_TIMEOUT')
            text = bytes(output).decode('utf-8', errors='replace')
            if code != 0:
                return SshResult(False, failure_code='SSH_CONNECTION_FAILED')
            return SshResult(True, text)
        finally:
            try:
                selector.close()
            except Exception:
                pass
            try:
                process.stdout.close()
            except Exception:
                pass

    @staticmethod
    def _kill(process):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except (OSError, ProcessLookupError):
                pass
        try:
            process.wait(timeout=1)
        except Exception:
            pass
