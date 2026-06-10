import click
import sys
import os
from .utils import safe_echo

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        os.environ["PYTHONIOENCODING"] = "utf-8"


def echo(text: str = "", **kwargs):
    try:
        click.echo(safe_echo(str(text)), **kwargs)
    except UnicodeEncodeError:
        click.echo(safe_echo(str(text)).encode("ascii", "replace").decode("ascii"), **kwargs)


def echo_via_pager(text: str):
    click.echo_via_pager(safe_echo(str(text)))


def prompt(text: str, **kwargs):
    return click.prompt(safe_echo(str(text)), **kwargs)


def confirm(text: str, **kwargs):
    return click.confirm(safe_echo(str(text)), **kwargs)


def get_terminal_size():
    return click.get_terminal_size()
