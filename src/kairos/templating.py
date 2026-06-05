"""Jinja2 environment for the Kairos templates (autoescape ON)."""

import time
from pathlib import Path

from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from kairos import settings

TEMPLATES = Path(__file__).parent / "templates"

# Cache-busting token for static assets: process start time (new on each deploy/restart)
STATIC_VERSION = str(int(time.time()))


def create_env(extra_dir: Path | str | None = None) -> Environment:
    loaders = [FileSystemLoader(str(TEMPLATES))]
    if extra_dir is not None:
        loaders.insert(0, FileSystemLoader(str(extra_dir)))
    from jinja2 import ChoiceLoader
    env = Environment(loader=ChoiceLoader(loaders) if len(loaders) > 1 else loaders[0],
                      autoescape=select_autoescape(("html", "htm", "xml")))
    env.globals.update(static_v=STATIC_VERSION, P=settings.PREFIX,
                       BRAND=settings.BRAND, HOME_URL=settings.HOME_URL,
                       LEGAL=bool(settings.OPERATOR))
    return env


def render(env: Environment, template: str, status_code: int = 200, **context) -> HTMLResponse:
    return HTMLResponse(env.get_template(template).render(**context), status_code=status_code)
