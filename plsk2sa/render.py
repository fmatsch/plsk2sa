"""Minimales Template-Rendering: {{VAR}}-Platzhalter, keine Abhängigkeiten.

Bewusst nicht string.Template/Jinja: nginx-Configs enthalten $uri u. ä.,
die kein Templating-System anfassen darf.
"""

import re
from pathlib import Path

TEMPLATE_DIR = Path(__file__).parent / "templates"

_PLACEHOLDER = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


class RenderError(RuntimeError):
    pass


def load_template(name: str) -> str:
    path = TEMPLATE_DIR / name
    if not path.is_file():
        raise RenderError(f"Template fehlt: {path}")
    return path.read_text()


def render(text: str, mapping: dict) -> str:
    def sub(match):
        key = match.group(1)
        if key not in mapping:
            raise RenderError(f"Template-Variable ohne Wert: {key}")
        return str(mapping[key])

    return _PLACEHOLDER.sub(sub, text)


def render_template(name: str, mapping: dict) -> str:
    return render(load_template(name), mapping)
