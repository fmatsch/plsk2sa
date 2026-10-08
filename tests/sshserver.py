"""In-process SSH server for transport tests: password auth, runs exec
requests through the local `bash -c`. Test helper only."""

import logging
import socket
import subprocess
import threading

import paramiko

logging.getLogger("paramiko").addHandler(logging.NullHandler())  # no 'Socket exception' noise


class _Server(paramiko.ServerInterface):
    def __init__(self, password):
        self.password = password

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        if password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        threading.Thread(target=_handle_exec, args=(channel, command.decode()), daemon=True).start()
        return True


def _handle_exec(channel, command):
    stdin = b""
    while True:
        data = channel.recv(65536)
        if not data:
            break
        stdin += data
    proc = subprocess.run(["bash", "-c", command], input=stdin,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.stdout:
        channel.sendall(proc.stdout)
    if proc.stderr:
        channel.sendall_stderr(proc.stderr)
    channel.send_exit_status(proc.returncode)
    channel.close()


class FakeSSHServer:
    def __init__(self, password="secret", host_key=None):
        self.password = password
        self.host_key = host_key or paramiko.ECDSAKey.generate()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self._transports = []
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(self.host_key)
            try:
                t.start_server(server=_Server(self.password))
            except (EOFError, paramiko.SSHException, OSError):
                t.close()  # client aborted the handshake (e.g. host key rejected)
                continue
            self._transports.append(t)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        for t in self._transports:
            t.close()
