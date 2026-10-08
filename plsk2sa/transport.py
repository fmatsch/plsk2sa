"""Transports: how a command reaches a host.

LocalTransport    runs the command on this machine.
OpenSSHTransport  shells out to the system `ssh` binary (CLI use; honours
                  ~/.ssh/config, agent forwarding, ProxyJump).
ParamikoTransport pure-Python SSH client (GUI use; password, key and agent
                  auth work identically on Windows, macOS and Linux).

All transports take an argv list and return a subprocess.CompletedProcess
with text stdout/stderr, so the Runner does not care which one it talks to.
"""

import base64
import hashlib
import logging
import shlex
import subprocess
import threading
from pathlib import Path
from typing import List, Optional

log = logging.getLogger("plsk2sa")

CHUNK = 1024 * 1024


class TransportError(RuntimeError):
    """The connection itself failed (as opposed to a command exiting non-zero)."""


class AuthenticationFailed(TransportError):
    pass


class HostKeyMismatch(TransportError):
    pass


class HostKeyUnknown(TransportError):
    """Raised when the server's host key is not trusted yet; carries what the
    user needs to decide."""

    def __init__(self, host, port, key_type, fingerprint):
        super().__init__(f"Unknown host key for {host}:{port} ({fingerprint})")
        self.host = host
        self.port = port
        self.key_type = key_type
        self.fingerprint = fingerprint


class Transport:
    def exec(self, argv: List[str], *, stdin_text: Optional[str] = None,
             stdin_path=None, stdout_path=None) -> subprocess.CompletedProcess:
        raise NotImplementedError

    def close(self):
        pass


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _run_subprocess(argv, stdin_text, stdin_path, stdout_path):
    stdin_file = open(stdin_path, "rb") if stdin_path else None
    stdout_file = open(stdout_path, "wb") if stdout_path else None
    try:
        cp = subprocess.run(
            argv,
            input=stdin_text.encode("utf-8") if stdin_file is None and stdin_text is not None else None,
            stdin=stdin_file,
            stdout=stdout_file if stdout_file else subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    finally:
        if stdin_file:
            stdin_file.close()
        if stdout_file:
            stdout_file.close()
    return subprocess.CompletedProcess(
        argv, cp.returncode,
        "" if stdout_file else _decode(cp.stdout or b""),
        _decode(cp.stderr or b""),
    )


class LocalTransport(Transport):
    def exec(self, argv, *, stdin_text=None, stdin_path=None, stdout_path=None):
        return _run_subprocess(list(argv), stdin_text, stdin_path, stdout_path)


class OpenSSHTransport(Transport):
    def __init__(self, host: str, ssh_options=None):
        self.host = host
        self.ssh_options = list(ssh_options or [])

    def argv(self, argv: List[str]) -> List[str]:
        remote = " ".join(shlex.quote(a) for a in argv)
        return ["ssh", *self.ssh_options, self.host, remote]

    def exec(self, argv, *, stdin_text=None, stdin_path=None, stdout_path=None):
        return _run_subprocess(self.argv(argv), stdin_text, stdin_path, stdout_path)


def fingerprint(key) -> str:
    """OpenSSH-style SHA256 fingerprint of a Paramiko public key."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def known_hosts_name(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


class ParamikoTransport(Transport):
    def __init__(self, client, host: str, port: int):
        self._client = client
        self.host = host
        self.port = port

    @classmethod
    def connect(cls, *, host: str, port: int = 22, user: str = "root",
                auth: str = "agent", password: Optional[str] = None,
                key_path: Optional[str] = None, passphrase: Optional[str] = None,
                known_hosts_file=None, accept_fingerprint: Optional[str] = None,
                timeout: float = 15.0) -> "ParamikoTransport":
        """Open an authenticated connection.

        auth: "password" | "key" | "agent" (agent + default keys in ~/.ssh).
        Unknown host keys raise HostKeyUnknown unless accept_fingerprint
        equals the offered key's fingerprint; accepted keys are stored in
        known_hosts_file. A changed key is always an error.
        """
        import socket

        import paramiko

        client = paramiko.SSHClient()
        try:
            client.load_system_host_keys()
        except OSError:
            pass
        known_hosts_file = Path(known_hosts_file) if known_hosts_file else None
        if known_hosts_file and known_hosts_file.is_file():
            client.load_host_keys(str(known_hosts_file))

        class _Policy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, cl, hostname, key):
                fp = fingerprint(key)
                if accept_fingerprint and accept_fingerprint == fp:
                    cl.get_host_keys().add(hostname, key.get_name(), key)
                    if known_hosts_file:
                        known_hosts_file.parent.mkdir(parents=True, exist_ok=True)
                        cl.save_host_keys(str(known_hosts_file))
                    return
                raise HostKeyUnknown(host, port, key.get_name(), fp)

        client.set_missing_host_key_policy(_Policy())

        kwargs = dict(hostname=host, port=port, username=user, timeout=timeout,
                      banner_timeout=timeout, auth_timeout=timeout)
        if auth == "password":
            kwargs.update(password=password or "", look_for_keys=False, allow_agent=False)
        elif auth == "key":
            if not key_path:
                raise TransportError("No private key file given")
            kwargs.update(key_filename=str(Path(key_path).expanduser()),
                          passphrase=passphrase or None,
                          look_for_keys=False, allow_agent=False)
        elif auth == "agent":
            kwargs.update(look_for_keys=True, allow_agent=True)
        else:
            raise TransportError(f"Unknown auth method: {auth}")

        try:
            client.connect(**kwargs)
        except HostKeyUnknown:
            client.close()
            raise
        except paramiko.BadHostKeyException as e:
            client.close()
            raise HostKeyMismatch(
                f"The host key of {host} has CHANGED (expected {fingerprint(e.expected_key)}, "
                f"got {fingerprint(e.key)}). Refusing to connect - this can indicate a "
                f"man-in-the-middle attack or a re-installed server."
            ) from None
        except paramiko.PasswordRequiredException:
            client.close()
            raise AuthenticationFailed("The private key is encrypted - enter its passphrase") from None
        except paramiko.AuthenticationException:
            client.close()
            raise AuthenticationFailed("Authentication failed - check user name and password/key") from None
        except paramiko.SSHException as e:
            client.close()
            raise TransportError(f"SSH error: {e}") from None
        except (socket.timeout, TimeoutError):
            client.close()
            raise TransportError(f"Connection to {host}:{port} timed out") from None
        except (socket.gaierror,):
            client.close()
            raise TransportError(f"Cannot resolve host name: {host}") from None
        except OSError as e:
            client.close()
            raise TransportError(f"Cannot connect to {host}:{port}: {e}") from None

        client.get_transport().set_keepalive(30)
        return cls(client, host, port)

    # ------------------------------------------------------------------
    def is_alive(self) -> bool:
        t = self._client.get_transport()
        return bool(t and t.is_active())

    def host_key(self):
        return self._client.get_transport().get_remote_server_key()

    def host_key_fingerprint(self) -> str:
        return fingerprint(self.host_key())

    def host_key_line(self) -> str:
        """known_hosts line for this server, to pin it on another machine."""
        key = self.host_key()
        return f"{known_hosts_name(self.host, self.port)} {key.get_name()} {key.get_base64()}"

    def exec(self, argv, *, stdin_text=None, stdin_path=None, stdout_path=None):
        transport = self._client.get_transport()
        if transport is None or not transport.is_active():
            raise TransportError(f"Connection to {self.host} was lost - reconnect and retry")

        command = " ".join(shlex.quote(a) for a in argv)
        chan = transport.open_session()
        chan.exec_command(command)

        out_file = open(stdout_path, "wb") if stdout_path else None
        out_buf, err_buf = [], []

        def pump(recv, sink_file, buf):
            while True:
                data = recv(CHUNK)
                if not data:
                    break
                if sink_file is not None:
                    sink_file.write(data)
                else:
                    buf.append(data)

        readers = [
            threading.Thread(target=pump, args=(chan.recv, out_file, out_buf), daemon=True),
            threading.Thread(target=pump, args=(chan.recv_stderr, None, err_buf), daemon=True),
        ]
        for t in readers:
            t.start()
        try:
            if stdin_path:
                with open(stdin_path, "rb") as f:
                    while True:
                        block = f.read(CHUNK)
                        if not block:
                            break
                        chan.sendall(block)
            elif stdin_text is not None:
                chan.sendall(stdin_text.encode("utf-8"))
            chan.shutdown_write()
            for t in readers:
                t.join()
            rc = chan.recv_exit_status()
        finally:
            if out_file:
                out_file.close()
            chan.close()

        return subprocess.CompletedProcess(
            argv, rc,
            "" if out_file else _decode(b"".join(out_buf)),
            _decode(b"".join(err_buf)),
        )

    def close(self):
        try:
            self._client.close()
        except Exception:
            pass
