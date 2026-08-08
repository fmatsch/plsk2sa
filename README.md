# plsk2sa — Plesk to Standalone

A framework for migrating Plesk hostings (web + mail + databases) to a
bare Ubuntu server (24.04 LTS) — no panel required afterwards.

A single controller (Python CLI) drives both servers over SSH —
agentless, nothing gets installed on either server. Every step is
**idempotent** (re-running is safe and doubles as a re-sync), every
mutating command can be previewed with **dry-run** (`-n`), and
everything is logged to `workdir/plsk2sa.log`.

Plesk does not invent anything of its own: it is essentially a config
generator plus a metadata database (`psa`) on top of standard services.
plsk2sa extracts that state and translates it into plain, panel-free
configuration.

## Target stack

| Area          | Implementation                                                  |
|---------------|-----------------------------------------------------------------|
| Web           | nginx + PHP-FPM (dedicated pool and system user per domain)     |
| Databases     | MariaDB (dump/restore, fresh credentials)                       |
| Mail (inbound)| Postfix, virtual domains, delivery via LMTP                     |
| Mail (storage)| Dovecot, Maildir under `/var/vmail`, passwd-file auth           |
| Mail (signing)| OpenDKIM (new keys, DNS records are generated)                  |
| SSL           | certbot (`--nginx`), issued fresh after the DNS switch          |

## Installation (on the controller)

The controller is ideally the **new Ubuntu server itself**
(`new_server: local` in the config); it then pulls all rsyncs directly
from the old server. Alternatively use a third machine with SSH access
to both servers (mind SSH agent forwarding in that case).

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
```

This provides the `plsk2sa` command (or `.venv/bin/plsk2sa`).

## Configuration

```bash
cp plsk2sa.example.yaml plsk2sa.yaml
```

Required fields: `old_server` (SSH target of the Plesk server, root)
and `mail_hostname` (FQDN of the new mail server — must match the PTR
record of the new IP). Everything else is documented in the example file.

**Warning:** the workdir contains plaintext mail passwords and database
dumps. The default is therefore `~/plsk2sa-work` — deliberately **not**
a Dropbox/cloud-synced folder — and it is chmod 700.

## Workflow

```bash
plsk2sa export       # read the Plesk server -> manifest, DB dumps, mail passwords
# review workdir/manifest.json (docroots, PHP version, mailboxes)
plsk2sa provision    # set up the base stack on the new server
plsk2sa migrate      # all domains: config + data (or: --domain example.com)
plsk2sa verify       # check services, ports, HTTP, mail accounts, DKIM
```

Every command accepts `-n`/`--dry-run` — mutating commands are then
only printed. Read-only operations (export, checks) still run, so the
plan stays realistic.

On migration day: [docs/cutover.md](docs/cutover.md) — final data sync
via `plsk2sa export && plsk2sa sync`, then switch DNS and run certbot.

## Architecture

```
plsk2sa/
├── cli.py            commands: export | provision | migrate | sync | verify
├── config.py         load + validate plsk2sa.yaml
├── runner.py         command execution local/SSH, dry-run, quoting, logging
├── manifest.py       data model of the migration (JSON, validated)
├── plesk_export.py   reads psa DB + Plesk CLI, produces manifest + dumps
├── render.py         {{VAR}} templates (deliberately no Jinja — nginx $vars!)
├── modules/          idempotent migration modules
│   ├── system.py     packages, vmail, Postfix/Dovecot/OpenDKIM base config
│   ├── web.py        site user, docroot rsync, PHP-FPM pool, vhost
│   ├── database.py   create DBs, import dumps, manage credentials
│   ├── mail.py       accounts (original passwords as hashes), aliases, maildirs
│   └── dkim.py       generate keys, emit DNS records
└── templates/        nginx, PHP-FPM, Dovecot, Postfix, OpenDKIM
```

Each module implements `provision()`, `migrate_domain()`,
`sync_domain()` and `verify()` — additional areas (e.g. FTP, cron) can
be added as another module and registered in
`modules/__init__.py:build_modules`.

## Deliberate decisions

- **Certificates are not migrated** — they are issued fresh via certbot
  after the DNS switch.
- **Database users get new passwords** (Plesk does not hand over the
  old ones cleanly). They live in `workdir/secrets/db-credentials.tsv`,
  stay stable across repeated runs, and must be entered into the app
  configs (`wp-config.php` etc.) after migration.
- **Mail passwords are preserved** (`plesk sbin mail_auth_view` reveals
  them; they end up as SHA512-CRYPT hashes in `/etc/dovecot/users`).
  Users won't notice the migration.
- **Cron jobs** are only backed up (`workdir/crontabs.tar`) and carried
  over manually.

## Tests

Unit tests run without any servers and without dependencies:

```bash
python3 -m unittest discover -s tests -v
```

## Mail prerequisites (cannot be automated)

- Outbound **port 25** unblocked by the new server's hosting provider.
- **PTR/reverse DNS** of the new IP points to `mail_hostname`.
- After the switch: update SPF to the new IP and publish the DKIM
  records from `workdir/dns/*.dkim.txt`.

## Status

Working state, tested at unit level. The Plesk read paths (psa SQL,
`mail_auth_view` table format) are written against the documented Plesk
structures but have not yet been validated against a live Plesk
instance — do a read-only trial run (`plsk2sa export`) first and check
the generated manifest against the raw outputs in `workdir/raw/`.

Note: code comments and CLI messages are currently in German.
