"""Module registry. Each module encapsulates one service area and is
idempotent - running it repeatedly is safe and serves as re-sync.

Lifecycle:
  provision()            once: base stack on the new server
  migrate_domain(domain) per domain: configuration + data
  sync_domain(domain)    per domain: only pull data again (cutover)
  verify()               checks; list of (ok: bool, message: str)
"""

from typing import List, Tuple

from ..context import Context
from ..manifest import Domain


class Module:
    name = "base"

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.runner = ctx.runner
        self.config = ctx.config

    def provision(self):
        pass

    def migrate_domain(self, domain: Domain):
        pass

    def sync_domain(self, domain: Domain):
        pass

    def verify(self) -> List[Tuple[bool, str]]:
        return []


def build_modules(ctx: Context) -> List[Module]:
    from . import database, dkim, mail, system, web

    return [
        system.SystemModule(ctx),
        web.WebModule(ctx),
        database.DatabaseModule(ctx),
        mail.MailModule(ctx),
        dkim.DkimModule(ctx),
    ]
