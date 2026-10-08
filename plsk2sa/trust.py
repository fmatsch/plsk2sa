"""Temporary server-to-server SSH access.

Web files and mailboxes are copied by rsync running on the NEW server and
pulling from the OLD one - the data never passes through the computer
that runs plsk2sa. For that, the new server needs to log in to the old
one. This module:

  1. generates a throw-away ed25519 key on the new server,
  2. appends its public key to the old server's authorized_keys
     (tagged with a marker, restricted to the new server's IP and with
     forwarding/pty disabled),
  3. pins the old server's host key on the new server (strict checking),
  4. verifies that login works,

and teardown() removes everything again - the pipeline calls it in a
finally block, so it also runs after errors and cancellation.

Manual cleanup on the old server, should the program be killed hard:
    grep -vF plsk2sa-temporary ~/.ssh/authorized_keys > /tmp/ak && cat /tmp/ak > ~/.ssh/authorized_keys
"""

import logging
import re
import shlex

from .context import Context

log = logging.getLogger("plsk2sa")

KEY_PATH = "/root/.ssh/plsk2sa_transfer"
KNOWN_HOSTS_PATH = "/root/.ssh/plsk2sa_known_hosts"
MARKER = "plsk2sa-temporary"

SETUP_PURPOSE = ("Add a temporary SSH key (comment 'plsk2sa-temporary') to ~/.ssh/authorized_keys "
                 "so the target server can pull the data; creates the file if it is missing")
TEARDOWN_PURPOSE = "Remove the temporary SSH key from ~/.ssh/authorized_keys again"

RE_PUBKEY = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/=]+ " + re.escape(MARKER) + r"$")
RE_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class TrustError(RuntimeError):
    pass


def _split_target(target: str):
    user, _, host = target.rpartition("@")
    return (user or "root"), host


_REMOVE_FROM_AUTHORIZED_KEYS = f"""
f=~/.ssh/authorized_keys
if [ -f "$f" ]; then
    grep -vF {MARKER} "$f" > "$f.plsk2sa.tmp" || true
    cat "$f.plsk2sa.tmp" > "$f"
    rm -f "$f.plsk2sa.tmp"
fi
"""


def setup(ctx: Context, *, old_host_key_line: str, restrict_ip: bool = True):
    r = ctx.runner
    cfg = ctx.config
    if r.dry_run:
        # Nothing is generated on the target in a preview, so the steps below cannot run -
        # but the change to the Plesk server must still be announced as "would change".
        log.info("dry-run: would set up temporary server-to-server SSH access")
        r.script(ctx.old, ":", purpose=SETUP_PURPOSE)
        return
    _, old_host = _split_target(ctx.old)

    log.info("[trust] Generating a temporary key on the target server")
    r.script(ctx.new, f"""set -euo pipefail
mkdir -p /root/.ssh
chmod 700 /root/.ssh
rm -f {KEY_PATH} {KEY_PATH}.pub
ssh-keygen -q -t ed25519 -N '' -C {MARKER} -f {KEY_PATH}
""")
    pub = r.run(ctx.new, ["cat", KEY_PATH + ".pub"], mutating=False).stdout.strip()
    if not RE_PUBKEY.match(pub):
        raise TrustError("Unexpected public key format from the target server")

    options = "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty"
    if restrict_ip:
        cp = r.run(ctx.new, ["bash", "-c",
                             r"""ip -4 route get "$(getent ahostsv4 "$0" | awk 'NR==1{print $1}')" 2>/dev/null """
                             r"""| sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1""",
                             old_host], mutating=False, check=False)
        src_ip = cp.stdout.strip()
        if RE_IPV4.match(src_ip):
            options = f'from="{src_ip}",' + options
            log.info("[trust] Key restricted to source address %s", src_ip)
        else:
            log.warning("[trust] Could not determine the target's source address; "
                        "the temporary key is not IP-restricted")

    line = f"{options} {pub}"
    log.info("[trust] Installing the temporary key on the Plesk server (removed again at the end)")
    r.script(ctx.old, f"""set -euo pipefail
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
{_REMOVE_FROM_AUTHORIZED_KEYS}
printf '%s\\n' {shlex.quote(line)} >> ~/.ssh/authorized_keys
""", purpose=SETUP_PURPOSE)

    r.put(ctx.new, KNOWN_HOSTS_PATH, old_host_key_line.strip() + "\n", mode="0600")
    cfg.transfer_key = KEY_PATH
    cfg.transfer_known_hosts = KNOWN_HOSTS_PATH

    cp = r.run(ctx.new, [
        "ssh", "-i", KEY_PATH, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", f"UserKnownHostsFile={KNOWN_HOSTS_PATH}", "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=10", "-p", str(cfg.old_ssh_port), ctx.old, "true",
    ], check=False)
    if cp.returncode != 0:
        raise TrustError(
            "The target server cannot log in to the Plesk server with the temporary key. "
            "If the target connects from a different address than it reaches the Plesk "
            "server from (NAT), disable the IP restriction. Details: "
            + (cp.stderr or "").strip()[:300])
    log.info("[trust] Server-to-server access works")


def teardown(ctx: Context) -> bool:
    """Remove the temporary key from both servers. Never raises."""
    r = ctx.runner
    ok = True
    try:
        r.script(ctx.old, "set -eu\n" + _REMOVE_FROM_AUTHORIZED_KEYS,
                 purpose=TEARDOWN_PURPOSE, revert=True)
    except Exception as e:  # noqa: BLE001 - cleanup must not mask the original error
        ok = False
        log.warning("[trust] Could not remove the temporary key from the Plesk server: %s\n"
                    "Remove the line containing '%s' from ~/.ssh/authorized_keys there.", e, MARKER)
    try:
        r.run(ctx.new, ["rm", "-f", KEY_PATH, KEY_PATH + ".pub", KNOWN_HOSTS_PATH])
    except Exception as e:  # noqa: BLE001
        ok = False
        log.warning("[trust] Could not remove the temporary key files from the target: %s", e)
    ctx.config.transfer_key = ""
    ctx.config.transfer_known_hosts = ""
    if ok:
        log.info("[trust] Temporary access removed")
    return ok
