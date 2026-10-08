# plsk2sa - Plesk to Standalone

[Project page](https://fmatsch.ist/plsk2sa/) · [Releases](https://github.com/fmatsch/plsk2sa/releases) · [Cutover checklist](docs/cutover.md)

Migrate Plesk hostings (web + mail + databases) to a bare Ubuntu server
(22.04 / 24.04) - no panel required afterwards. Comes with a **graphical
wizard** for Windows, macOS and Linux and a scriptable command line.

> **Standalone program, shown in your browser.** The download is one
> self-contained file - no Python, no installation, no internet connection
> needed. When started it opens its interface in your default web browser
> (a small web server that listens on your own computer only); there is no
> separate native window. Any current browser works.

Plesk does not invent anything of its own: it is essentially a config
generator plus a metadata database (`psa`) on top of standard services.
plsk2sa extracts that state and translates it into plain, panel-free
configuration.

## Graphical wizard

```
 1 Plesk server  ->  2 Checks  ->  3 Select domains  ->  4 Target server  ->  5 Migrate
```

1. **Connect** to the Plesk server over SSH (password, key file or SSH agent;
   unknown host keys are shown for you to confirm).
2. **Checks** run automatically: root access, Plesk and its database, rsync,
   readable mail passwords, disk space, subdomains and aliases that need
   manual work. Failures block you, warnings are explained.
3. **Select** what to migrate - domains are grouped by Plesk subscription,
   with PHP version, databases, mailboxes and sizes.
4. **Connect to the target** server; a second set of checks covers the OS,
   free space, reachability of the Plesk server, busy ports, outbound port 25,
   reverse DNS (PTR) and PHP version changes.
5. **Migrate** - say who hosts your DNS, then start with a *preview* (lists
   every command, changes nothing) and run for real with a live log. The result
   page shows the DNS changes, the new database credentials and next steps.
   Come back for a *final sync* on switch day.

**DNS.** The wizard asks who answers DNS queries for your domains:

- *Somewhere else* (registrar, Cloudflare, ...): plsk2sa reads the records Plesk
  holds and lists exactly which ones must change - A records and SPF entries
  with the old server's address, the old Plesk DKIM key to remove, the new DKIM
  record and the mail host's A record to add, IPv6 records to review.
- *This Plesk server* (its name servers answer): the zones must move with the
  domains, so you additionally get a complete zone file per domain with the new
  addresses, to copy or download and import at your new DNS provider. The
  name servers themselves are changed at your registrar.

Records that point to other addresses (a CDN, another host) are never touched.

**Changes on the Plesk server are always shown.** Before a run, the wizard lists
what will be changed there; while it runs, every change is announced in a banner
and the log the moment it happens; afterwards the result states whether the Plesk
server was left unchanged or restored. A preview only ever says "would change".

### Start it

**Download** the program for your system from the
[Releases](https://github.com/fmatsch/plsk2sa/releases) page and run it
(double-click, or `./plsk2sa` in a terminal). Your browser opens the wizard.
Releases are built by the CI when a `v*` tag is pushed; until the first one
exists, run it from source or build it yourself (see *Development*).
The executables are not code-signed: macOS asks you to confirm
(right-click > Open, or `xattr -d com.apple.quarantine plsk2sa`) and Windows
SmartScreen shows "More info > Run anyway".

**Or from source** (Python 3.9+):

```bash
pip install .
plsk2sa-gui            # same as: plsk2sa ui
```

**Try it without any server:** `plsk2sa ui --demo` runs the complete wizard
against simulated servers (invented data, nothing is contacted or changed).

### How data moves

Web files and mailboxes are copied by `rsync` running on the **target** and
pulling straight from the Plesk server, so large mailboxes never pass through
your computer. For that, plsk2sa sets up temporary server-to-server access
during a real run:

- a throw-away ed25519 key is generated on the target,
- its public key is appended to the Plesk server's `authorized_keys`, tagged
  `plsk2sa-temporary`, restricted to the target's IP and with forwarding and
  pty disabled,
- the Plesk server's host key (the one you confirmed) is pinned on the target,
- everything is removed again at the end - also after errors and after
  *Cancel*.

This is the only change made to the Plesk server, and it is announced as it
happens (the runner flags every mutating command sent to the Plesk server, so a
future change could not slip in unnoticed). If the program is killed hard,
remove the marked line yourself:
`grep -vF plsk2sa-temporary ~/.ssh/authorized_keys > /tmp/ak && cat /tmp/ak > ~/.ssh/authorized_keys`

### Security of the local interface

The wizard can run commands as root on your servers, so it is locked down: it
listens on `127.0.0.1` only, every request needs a random per-start token,
the `Host` header is checked against DNS rebinding, and a strict
Content-Security-Policy applies. Passwords are used to open the SSH connection
and are never stored, logged or written to disk. The working folder
(`~/plsk2sa-work`, outside any cloud-synced folder) does contain database dumps
and the mail passwords of the **selected** domains - treat it accordingly.

## Command line

The same engine runs headless; see `plsk2sa.example.yaml`.

```bash
cp plsk2sa.example.yaml plsk2sa.yaml
plsk2sa check        # pre-flight checks for both servers
plsk2sa export       # read the Plesk server -> manifest, DB dumps, mail passwords
# review workdir/manifest.json
plsk2sa provision    # set up the base stack on the new server
plsk2sa migrate      # all domains (or: --domain example.com)
plsk2sa verify       # services, ports, HTTP, mail accounts, DKIM
plsk2sa sync         # switch day: pull data again
plsk2sa dns --new-ip 203.0.113.20 --old-ip 203.0.113.10 [--plesk-dns]   # DNS plan / zone files
```

`-n` / `--dry-run` shows every mutating command without running it. The CLI
drives the system `ssh`; the usual place to run it is the new server itself
(`new_server: local`, Linux/macOS only). Server-to-server SSH access is then
your own business (agent forwarding or a key on the new server).

## Target stack

| Area           | Implementation                                              |
|----------------|-------------------------------------------------------------|
| Web            | nginx + PHP-FPM (dedicated pool and system user per domain) |
| Databases      | MariaDB (dump/restore, fresh credentials)                   |
| Mail (inbound) | Postfix, virtual domains, delivery via LMTP                 |
| Mail (storage) | Dovecot, Maildir under `/var/vmail`, passwd-file auth       |
| Mail (signing) | OpenDKIM (new keys, DNS records are generated)              |
| SSL            | certbot (`--nginx`), issued after the DNS switch            |

## Deliberate decisions and known limits

- **Certificates are not migrated** - they are issued fresh via certbot after
  the DNS switch ([docs/cutover.md](docs/cutover.md)).
- **Database users get new passwords** (Plesk does not hand over the old
  ones). They are saved in `workdir/secrets/db-credentials.tsv`, stay stable
  across runs and must be entered into the application configs.
- **Mail passwords are preserved** (`plesk sbin mail_auth_view`; stored as
  SHA512-CRYPT hashes in Dovecot). Mailboxes whose password Plesk cannot reveal
  are skipped and reported.
- **Not migrated automatically:** subdomains, domain aliases, cron jobs
  (backed up to `workdir/crontabs.tar`) and FTP accounts. The checks list the
  subdomains and aliases they find. DNS is *planned*, not applied: plsk2sa never
  changes records at a DNS provider and does not run a DNS server for you.
- **PHP version:** the target uses the PHP of its Ubuntu release (8.1 on 22.04,
  8.3 on 24.04); the checks warn when a site ran a different version on Plesk.
- **Windows:** the wizard works on Windows; command-line `new_server: local`
  mode needs Linux or macOS.

## Architecture

```
plsk2sa/
├── cli.py            commands: ui | check | export | provision | migrate | sync | verify
├── ui/               local web GUI: server.py (HTTP, security), backend.py (logic), static/
├── pipeline.py       GUI run: export -> provision -> trust -> domains -> verify -> cleanup
├── checks.py         pre-flight checks for both servers (shared by GUI and CLI)
├── dnsplan.py        DNS planning: record changes and importable zone files
├── trust.py          temporary server-to-server SSH key (setup / teardown)
├── plesk_export.py   psa database + Plesk CLI: discover() and export()
├── transport.py      local / OpenSSH / Paramiko transports, host key handling
├── runner.py         command execution, dry-run, logging
├── manifest.py       validated data model of a migration (JSON)
├── demo.py           simulated servers for `--demo` and the tests
├── modules/          idempotent migration modules: system, web, database, mail, dkim
└── templates/        nginx, PHP-FPM, Dovecot, Postfix, OpenDKIM
```

Each module implements `provision()`, `migrate_domain()`, `sync_domain()` and
`verify()`; new areas (FTP, cron, ...) are one more module in
`modules/__init__.py:build_modules`.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e . pyinstaller
.venv/bin/python -m unittest discover -s tests -v    # no servers needed
.venv/bin/python -m plsk2sa ui --demo                # click through the wizard
```

The tests include an in-process SSH server, so the Paramiko transport is
exercised over the real protocol. To build the executable for your platform:

```bash
pyinstaller --noconfirm --clean packaging/plsk2sa.spec
python packaging/smoke_test.py dist/plsk2sa          # drives the wizard in demo mode
```

GitHub Actions ([.github/workflows/build.yml](.github/workflows/build.yml))
runs the tests on Linux, Windows and macOS, builds the three executables,
smoke-tests each, and attaches them to a release when a `v*` tag is pushed.

## Status

Early but working. Unit and integration tests cover the transport, checks,
pipeline, trust handling and the GUI server; the wizard has been exercised
end-to-end against the built-in simulated servers. **Not yet validated
against a live Plesk instance:** the Plesk read paths (psa SQL, `mail_auth_view`
table format, `webspace_id`/`php_handler_id` columns) follow the documented
structures; each is fail-soft (the wizard shows a note instead of stopping).
Do a read-only trial first - connecting, the checks and the preview change
nothing on the target.

## License

MIT - see [LICENSE](LICENSE).
