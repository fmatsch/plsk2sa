"""Minimal template rendering: {{VAR}} placeholders, no dependencies.

Deliberately not string.Template/Jinja: nginx configs contain $uri and
similar variables that no templating system may touch.
"""

import re
from pathlib import Path

from .fsutil import read_text

TEMPLATE_DIR = Path(__file__).parent / "templates"

_PLACEHOLDER = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


class RenderError(RuntimeError):
    pass


def load_template(name: str) -> str:
    path = TEMPLATE_DIR / name
    if not path.is_file():
        raise RenderError(f"Template missing: {path}")
    return read_text(path)


def render(text: str, mapping: dict) -> str:
    def sub(match):
        key = match.group(1)
        if key not in mapping:
            raise RenderError(f"Template variable without value: {key}")
        return str(mapping[key])

    return _PLACEHOLDER.sub(sub, text)


def render_template(name: str, mapping: dict) -> str:
    return render(load_template(name), mapping)
