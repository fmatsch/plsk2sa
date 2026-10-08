"""Shared test fixtures: a context wired to the simulated demo servers."""

import atexit
import shutil
import tempfile

from plsk2sa.config import Config
from plsk2sa.context import Context
from plsk2sa.demo import make_demo_transports
from plsk2sa.runner import Runner


def temp_workdir() -> str:
    path = tempfile.mkdtemp(prefix="plsk2sa-test-")
    atexit.register(shutil.rmtree, path, ignore_errors=True)
    return path


def demo_context(dry_run=False, workdir=None, **config_overrides):
    transports = make_demo_transports(delay=0)
    runner = Runner(dry_run=dry_run)
    runner.register("root@old", transports["old"])
    runner.register("root@new", transports["new"])
    cfg = Config(old_server="root@old", new_server="root@new",
                 mail_hostname="mail.acme-shop.com", workdir=str(workdir or temp_workdir()),
                 php_version="8.3", **config_overrides)
    return Context(cfg, runner)
