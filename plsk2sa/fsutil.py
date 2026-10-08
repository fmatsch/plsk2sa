"""File helpers with fixed encoding and line endings.

Python's text-mode defaults differ per platform (cp1252 and CRLF on
Windows); data we write here is later parsed or sent to Linux servers,
so it is always UTF-8 with LF.
"""

from pathlib import Path


def write_text(path, text: str):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def read_text(path) -> str:
    with open(path, "r", encoding="utf-8", newline=None) as f:
        return f.read()


def write_secret(path, text: str):
    """Like write_text, but restricted to the current user (best effort on Windows)."""
    write_text(path, text)
    try:
        Path(path).chmod(0o600)
    except OSError:
        pass
