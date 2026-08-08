"""Modul-Registry. Jedes Modul kapselt einen Dienst-Bereich und ist
idempotent — mehrfaches Ausführen ist sicher und dient dem Nachsync.

Lebenszyklus:
  provision()            einmalig: Basis-Stack auf dem neuen Server
  migrate_domain(domain) pro Domain: Konfiguration + Daten
  sync_domain(domain)    pro Domain: nur Daten nachziehen (Cutover)
  verify()               Checks; Liste von (ok: bool, meldung: str)
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
