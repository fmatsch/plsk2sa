set -euo pipefail
# Postfix-Grundkonfiguration für virtuelle Domains — von plsk2sa generiert.

touch /etc/postfix/virtual_domains /etc/postfix/vmailbox /etc/postfix/virtual
postmap /etc/postfix/vmailbox /etc/postfix/virtual

postconf -e "myhostname = {{MAIL_HOSTNAME}}"
postconf -e "mydestination = localhost"
postconf -e "virtual_mailbox_domains = /etc/postfix/virtual_domains"
postconf -e "virtual_mailbox_maps = hash:/etc/postfix/vmailbox"
postconf -e "virtual_alias_maps = hash:/etc/postfix/virtual"
postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"
postconf -e "smtpd_sasl_auth_enable = yes"
postconf -e "smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination"
postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated permit_mynetworks reject_unauth_destination reject_unknown_recipient_domain"
postconf -e "smtpd_milters = local:opendkim/opendkim.sock"
postconf -e "non_smtpd_milters = local:opendkim/opendkim.sock"
postconf -e "milter_default_action = accept"
postconf -e "message_size_limit = 52428800"
# TLS-Zertifikat wird nach dem certbot-Lauf umgestellt (docs/cutover.md)

# Submission 587 (STARTTLS) und SMTPS 465
postconf -M "submission/inet=submission inet n - y - - smtpd"
postconf -P "submission/inet/syslog_name=postfix/submission"
postconf -P "submission/inet/smtpd_tls_security_level=encrypt"
postconf -P "submission/inet/smtpd_sasl_auth_enable=yes"
postconf -M "smtps/inet=smtps inet n - y - - smtpd"
postconf -P "smtps/inet/syslog_name=postfix/smtps"
postconf -P "smtps/inet/smtpd_tls_wrappermode=yes"
postconf -P "smtps/inet/smtpd_sasl_auth_enable=yes"
