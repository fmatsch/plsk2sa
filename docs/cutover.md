# Cutover checklist

## Preparation (days ahead)

- [ ] Lower the TTL of all relevant DNS records (A, AAAA, MX) to **300 s**.
- [ ] At the new server's hosting provider: get **outbound port 25**
      unblocked and set the **PTR/reverse DNS** of the IP to `mail_hostname`.
- [ ] The full migration finished and its verification passed (wizard: *Migrate*, or
      `plsk2sa migrate` and `plsk2sa verify`).
- [ ] Test the websites locally:
      `curl -H 'Host: example.com' http://NEW_IP/`
- [ ] App configs (wp-config.php etc.) updated with the new database
      credentials from `workdir/secrets/db-credentials.tsv`.
- [ ] Test IMAP login against the new IP (port 143/993, existing
      mail password).
- [ ] Publish the DKIM records from `workdir/dns/*.dkim.txt` already
      (harmless as long as the old server doesn't sign).

## Migration day

1. [ ] Stop mail acceptance on the **old** server so nothing new
       arrives: `systemctl stop postfix`
       (sending servers retry automatically — nothing is lost).
2. [ ] **Final data sync**. In the wizard, run through the steps again and choose
       *Final sync only* in the last step (untick *Preview only* first). On the
       command line:
       ```bash
       plsk2sa export && plsk2sa sync
       ```
       (export pulls fresh DB dumps and password lists, sync re-imports
       the dumps and rsyncs web files + maildirs).
3. [ ] **Switch DNS**: point A/AAAA of the domains and of the mail
       hostname plus MX to the new IP / new mail hostname.
4. [ ] **Obtain certificates** (as soon as DNS points to the new IP):
       ```bash
       certbot --nginx -d example.com -d www.example.com
       certbot certonly --nginx -d mail.example.com
       ```
5. [ ] Point Postfix/Dovecot at the Let's Encrypt certificate:
       ```bash
       postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/mail.example.com/fullchain.pem"
       postconf -e "smtpd_tls_key_file  = /etc/letsencrypt/live/mail.example.com/privkey.pem"
       ```
       In `/etc/dovecot/conf.d/10-ssl.conf` set `ssl_cert`/`ssl_key` to
       the same paths, then `systemctl reload postfix dovecot`.
6. [ ] Update the **SPF record** to the new IP; leave DMARC unchanged
       or create one.

## Post-checks

- [ ] `plsk2sa verify` again — all green?
- [ ] Send a test mail from outside to both domains and fetch it.
- [ ] Send a test mail to an external mailbox (e.g. Gmail), check the
      headers: SPF=pass, DKIM=pass ([mail-tester.com](https://www.mail-tester.com) helps).
- [ ] Open the websites via HTTPS, check certificate and redirects.
- [ ] Carry over cron jobs from `workdir/crontabs.tar` manually
      (`crontab -u <user> -e`).
- [ ] Test certbot renewal: `certbot renew --dry-run`.
- [ ] Keep the old Plesk server for another **2–4 weeks** (DNS
      stragglers, forgotten cron jobs, leftover data), then cancel it.
